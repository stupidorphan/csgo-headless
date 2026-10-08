#include "hc/state.hpp"
#include "hc/wire.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string_view>

namespace hc {
namespace {
using Json = nlohmann::json;
constexpr std::uint32_t Unsigned = 1u, Coord = 1u << 1, NoScale = 1u << 2,
    Normal = 1u << 5, Exclude = 1u << 6, InsideArray = 1u << 8,
    Collapsible = 1u << 11, CoordMP = 1u << 12, CoordMPLow = 1u << 13,
    CoordMPIntegral = 1u << 14, CellCoord = 1u << 15, CellLow = 1u << 16,
    CellIntegral = 1u << 17, Often = 1u << 18, VarInt = 1u << 19;
unsigned width(std::uint32_t value) { return value ? std::bit_width(value) : 1; }
void require(bool ok, const std::string& reason) { if (!ok) throw StateError(reason); }
std::string joined(const std::string& prefix, const std::string& name) {
    return prefix.empty() ? name : prefix + "." + name;
}
std::string safe_string(std::span<const std::uint8_t> data) {
    auto end = std::find(data.begin(), data.end(), std::uint8_t{});
    return std::string(data.begin(), end);
}
std::uint64_t big_endian(std::span<const std::uint8_t> data) {
    std::uint64_t result = 0;
    for (auto byte : data) result = (result << 8) | byte;
    return result;
}
Json opaque_fields(const Proto& message) {
    Json result = Json::array();
    static constexpr char hex[] = "0123456789abcdef";
    for (const auto& field : message.all_fields()) {
        Json item{{"field", field.number}, {"wire", field.wire_type}};
        if (field.wire_type == 0) item["value"] = field.varint;
        else {
            std::string value;
            value.reserve(field.data.size() * 2);
            for (auto byte : field.data) { value += hex[byte >> 4]; value += hex[byte & 15]; }
            item["hex"] = std::move(value);
        }
        result.push_back(std::move(item));
    }
    return result;
}
struct Prop {
    int type{};
    std::string name, table, path;
    std::uint32_t flags{};
    unsigned priority{}, bits{}, elements{};
    float low{}, high{};
    std::shared_ptr<Prop> element;
};
struct Table { std::string name; std::vector<Prop> props; };
struct Class { int id{}; std::string name, table; std::vector<Prop> flat; };
Prop prop_from_json(const Json& data) {
    Prop prop;
    prop.type = data.at("type").get<int>();
    prop.name = data.at("name").get<std::string>();
    prop.flags = data.value("flags", 0u);
    prop.priority = data.value("priority", 0u);
    prop.table = data.value("table", std::string{});
    prop.elements = data.value("elements", 0u);
    prop.bits = data.value("bits", 0u);
    prop.low = data.value("low", 0.0f);
    prop.high = data.value("high", 0.0f);
    require(prop.type >= 0 && prop.type <= 7 && prop.priority <= 255 && prop.bits <= 64 &&
            prop.elements <= 2048 && std::isfinite(prop.low) && std::isfinite(prop.high), "Invalid send property metadata");
    return prop;
}
Table table_from_json(const Json& data) {
    Table table;
    table.name = data.at("name").get<std::string>();
    require(!table.name.empty(), "Empty send table name");
    for (const auto& item : data.at("props")) {
        auto prop = prop_from_json(item);
        if (prop.type == 5) {
            require(!table.props.empty() && (table.props.back().flags & InsideArray) &&
                    table.props.back().type != 6 && table.props.back().type != 5,
                    "Array property is missing its preceding element description");
            prop.element = std::make_shared<Prop>(table.props.back());
        }
        table.props.push_back(std::move(prop));
    }
    require(table.props.size() <= 4096, "Send table exceeds property limit");
    return table;
}
Table table_from_proto(const Proto& data) {
    Json table{{"name", data.get_string(2)}, {"props", Json::array()}};
    for (const auto& item : data.get_messages(4)) {
        table["props"].push_back({{"type", item.get_i32(1)}, {"name", item.get_string(2)},
            {"flags", item.get_u32(3)}, {"priority", item.get_u32(4)}, {"table", item.get_string(5)},
            {"elements", item.get_u32(6)}, {"low", item.get_float(7)}, {"high", item.get_float(8)},
            {"bits", item.get_u32(9)}});
    }
    return table_from_json(table);
}

float coordinate(BitReader& in) {
    const bool integer = in.bit(), fraction = in.bit();
    if (!integer && !fraction) return 0;
    const bool negative = in.bit();
    const float whole = integer ? static_cast<float>(in.bits(14) + 1) : 0.0f;
    const float fract = fraction ? static_cast<float>(in.bits(5)) / 32.0f : 0.0f;
    return (negative ? -1.0f : 1.0f) * (whole + fract);
}
float coordinate_mp(BitReader& in, bool integral, bool low) {
    const bool small = in.bit(), integer = in.bit();
    if (integral && !integer) return 0;
    const bool negative = in.bit();
    const float whole = integer ? static_cast<float>(in.bits(small ? 11 : 14) + 1) : 0.0f;
    const float fract = integral ? 0.0f : static_cast<float>(in.bits(low ? 3 : 5)) / (low ? 8.0f : 32.0f);
    return (negative ? -1.0f : 1.0f) * (whole + fract);
}
float prop_float(BitReader& in, const Prop& prop) {
    float value;
    if (prop.flags & Coord) value = coordinate(in);
    else if (prop.flags & CoordMP) value = coordinate_mp(in, false, false);
    else if (prop.flags & CoordMPLow) value = coordinate_mp(in, false, true);
    else if (prop.flags & CoordMPIntegral) value = coordinate_mp(in, true, false);
    else if (prop.flags & NoScale) value = in.float32();
    else if (prop.flags & Normal) {
        const auto negative = in.bit();
        value = static_cast<float>(in.bits(11)) / 2047.0f;
        if (negative) value = -value;
    } else if (prop.flags & (CellCoord | CellLow | CellIntegral)) {
        require(prop.bits <= 32, "Cell coordinate has an invalid bit width");
        value = static_cast<float>(in.bits(prop.bits));
        if (!(prop.flags & CellIntegral)) {
            const bool low = (prop.flags & CellLow) != 0;
            value += static_cast<float>(in.bits(low ? 3 : 5)) / (low ? 8.0f : 32.0f);
        }
    } else {
        require(prop.bits > 0 && prop.bits <= 32, "Quantized float has an invalid bit width");
        const auto encoded = in.bits(prop.bits);
        const auto divisor = (std::uint64_t{1} << prop.bits) - 1;
        value = prop.low + (prop.high - prop.low) * static_cast<float>(static_cast<double>(encoded) / divisor);
    }
    require(std::isfinite(value), "Nonfinite entity property");
    return value;
}
Json decode_prop(BitReader& in, const Prop& prop) {
    switch (prop.type) {
    case 0:
        if (prop.flags & VarInt) {
            const auto number = in.varuint32();
            if (prop.flags & Unsigned) return number;
            return static_cast<std::int32_t>((number >> 1) ^ (0u - (number & 1u)));
        }
        require(prop.bits > 0 && prop.bits <= 32, "Integer has an invalid bit width");
        if (prop.flags & Unsigned) return in.bits(prop.bits);
        return in.signed_bits(prop.bits);
    case 1: return prop_float(in, prop);
    case 2: case 3: {
        const auto x = prop_float(in, prop), y = prop_float(in, prop);
        if (prop.type == 3) return Json::array({x, y});
        float z;
        if (prop.flags & Normal) {
            const bool negative = in.bit();
            z = std::sqrt(std::max(0.0f, 1 - x * x - y * y));
            if (negative) z = -z;
        } else z = prop_float(in, prop);
        return Json::array({x, y, z});
    }
    case 4: {
        const auto count = in.bits(9);
        auto bytes = in.bytes(count);
        return std::string(bytes.begin(), bytes.end());
    }
    case 5: {
        require(bool(prop.element), "Array has no element metadata");
        const auto count = in.bits(width(prop.elements));
        require(count <= prop.elements, "Entity array exceeds declared element count");
        Json result = Json::array();
        for (std::uint32_t i = 0; i < count; ++i) result.push_back(decode_prop(in, *prop.element));
        return result;
    }
    case 7: {
        if (prop.flags & VarInt) {
            const auto number = in.varuint64();
            if (prop.flags & Unsigned) return number;
            return static_cast<std::int64_t>((number >> 1) ^ (std::uint64_t{} - (number & 1)));
        }
        const bool is_signed = !(prop.flags & Unsigned);
        require(prop.bits >= (is_signed ? 33u : 32u) && prop.bits <= 64, "Int64 has an invalid bit width");
        const bool negative = is_signed && in.bit();
        const std::uint64_t low = in.bits(32);
        const std::uint64_t high = in.bits(prop.bits - 32 - (is_signed ? 1 : 0));
        const std::uint64_t value = low | (high << 32);
        if (!is_signed) return value;
        return negative ? -static_cast<std::int64_t>(value) : static_cast<std::int64_t>(value);
    }
    default: throw StateError("Unflattened datatable in entity schema");
    }
}
void decode_fields(BitReader& in, const Class& cls, Json& fields) {
    const bool modern = in.bit();
    std::vector<std::size_t> indexes;
    int previous = -1;
    for (;;) {
        std::uint32_t delta = 0;
        if (modern && in.bit()) {
            ++previous;
        } else {
            if (modern && in.bit()) delta = in.bits(3);
            else {
                delta = in.bits(7);
                const auto extra = delta & 96u;
                if (extra) delta = (delta & 31u) | (in.bits(extra == 32 ? 2 : extra == 64 ? 4 : 7) << 5);
            }
            if (delta == 4095) break;
            previous += static_cast<int>(delta) + 1;
        }
        require(previous >= 0 && static_cast<std::size_t>(previous) < cls.flat.size(),
                "Entity field index exceeds exact send table for " + cls.name);
        indexes.push_back(static_cast<std::size_t>(previous));
        require(indexes.size() <= 4096, "Entity field list overflow");
    }
    for (auto index : indexes) fields[cls.flat[index].path] = decode_prop(in, cls.flat[index]);
}
const Json* suffix(const Json& fields, std::string_view name) {
    for (auto item = fields.begin(); item != fields.end(); ++item) {
        const auto& key = item.key();
        if (key == name || (key.size() > name.size() && key.ends_with(name) && key[key.size() - name.size() - 1] == '.'))
            return &item.value();
    }
    return nullptr;
}
}

struct State::Impl {
    struct Entity { int index{}, class_id{}, serial{}; Json fields = Json::object(); };
    using Entities = std::map<int, std::shared_ptr<Entity>>;
    struct StringEntry { std::string name; Bytes data; };
    struct Strings {
        std::string name;
        unsigned maximum{}, entry_bits{}, data_size{}, data_bits{};
        bool fixed{};
        std::vector<StringEntry> entries;
    };
    struct EventDescriptor { std::string name; std::vector<std::pair<int, std::string>> keys; };
    std::map<std::string, Table> tables;
    std::map<int, Class> classes;
    std::vector<std::string> dictionary;
    unsigned dictionary_bits{}, class_bits{1};
    std::vector<Strings> string_tables;
    std::map<int, Bytes> class_baselines;
    std::array<Entities, 2> baselines;
    std::map<std::int32_t, Entities> frames;
    Entities current;
    std::map<int, Json> users;
    std::map<int, EventDescriptor> descriptors;
    std::deque<Json> events;
    std::vector<std::pair<std::uint32_t, Proto>> outgoing;
    std::string map;
    int player_slot{-1}, max_clients{}, tick{}, snapshot_tick{-1};
    float interval{1.0f / 64};
    bool full_update{};
    Json round = Json::object();

    void event(Json value) {
        value["tick"] = tick;
        if (events.size() == 256) events.pop_front();
        events.push_back(std::move(value));
    }
    void clear() {
        string_tables.clear(); class_baselines.clear(); frames.clear(); current.clear(); users.clear();
        baselines = {}; descriptors.clear(); events.clear(); outgoing.clear(); map.clear();
        player_slot = -1; max_clients = 0; tick = 0; snapshot_tick = -1;
        interval = 1.0f / 64; full_update = false; round = Json::object();
    }
    const Table& table(const std::string& name) const {
        const auto item = tables.find(name);
        require(item != tables.end(), "Metadata is missing send table " + name);
        return item->second;
    }
    void flatten(Class& cls) {
        std::set<std::pair<std::string, std::string>> excluded;
        std::set<std::string> ancestry;
        std::function<void(const Table&, unsigned)> gather = [&](const Table& source, unsigned depth) {
            require(depth <= 64 && ancestry.insert(source.name).second, "Cyclic or excessively nested send table");
            for (const auto& prop : source.props) {
                if (prop.flags & Exclude) excluded.emplace(prop.table, prop.name);
                else if (prop.type == 6) gather(table(prop.table), depth + 1);
            }
            ancestry.erase(source.name);
        };
        gather(table(cls.table), 0);
        cls.flat.clear();
        std::function<void(const Table&, const std::string&, std::vector<Prop>&, unsigned)> iterate;
        std::function<void(const Table&, const std::string&, unsigned)> append;
        append = [&](const Table& source, const std::string& prefix, unsigned depth) {
            std::vector<Prop> pending;
            iterate(source, prefix, pending, depth);
            cls.flat.insert(cls.flat.end(), pending.begin(), pending.end());
        };
        iterate = [&](const Table& source, const std::string& prefix, std::vector<Prop>& pending, unsigned depth) {
            require(depth <= 64, "Send table nesting limit");
            for (const auto& prop : source.props) {
                if ((prop.flags & (Exclude | InsideArray)) || excluded.contains({source.name, prop.name})) continue;
                if (prop.type == 6) {
                    const auto child_prefix = joined(prefix, prop.name);
                    if (prop.flags & Collapsible) iterate(table(prop.table), child_prefix, pending, depth + 1);
                    else append(table(prop.table), child_prefix, depth + 1);
                } else {
                    auto flat = prop;
                    flat.path = joined(prefix, prop.name);
                    pending.push_back(std::move(flat));
                }
            }
        };
        append(table(cls.table), {}, 0);
        require(cls.flat.size() <= 4096, "Flattened class exceeds property limit");
        // Valve's priority pass swaps into the prefix. A stable sort of all props
        // would produce a different wire field index for displaced properties.
        std::set<unsigned> priorities{64};
        for (const auto& prop : cls.flat) priorities.insert(prop.priority);
        std::size_t start = 0;
        for (auto priority : priorities) {
            for (;;) {
                auto found = std::find_if(cls.flat.begin() + start, cls.flat.end(), [&](const Prop& prop) {
                    return prop.priority == priority || (priority == 64 && (prop.flags & Often));
                });
                if (found == cls.flat.end()) break;
                std::iter_swap(cls.flat.begin() + start, found);
                ++start;
            }
        }
    }
    void rebuild() {
        require(classes.size() <= 1024 && tables.size() <= 1024, "Entity metadata exceeds class/table limits");
        for (auto& [id, cls] : classes) flatten(cls);
        const auto count = classes.empty() ? 1u : static_cast<unsigned>(classes.rbegin()->first + 1);
        class_bits = width(count);
    }
    void user(const Strings& strings, unsigned index) {
        if (strings.name == "instancebaseline") {
            const auto& entry = strings.entries[index];
            std::size_t end = 0;
            const int id = std::stoi(entry.name, &end);
            require(end == entry.name.size() && classes.contains(id), "Invalid class baseline identifier");
            class_baselines[id] = entry.data;
        } else if (strings.name == "userinfo") {
            const auto& data = strings.entries[index].data;
            if (data.empty()) { users.erase(static_cast<int>(index) + 1); return; }
            // player_info_t is byte-swapped to network order. Version 2 carries
            // a version word and 128-byte names; the older layout has neither.
            require(data.size() >= 44, "Truncated player_info_t in userinfo table");
            const auto bytes = std::span<const std::uint8_t>(data);
            const bool version2 = big_endian(bytes.first(8)) == 0xfffffffffffff002ull;
            require(!version2 || data.size() >= 148, "Truncated version 2 player_info_t");
            Json info{{"entity_index", index + 1},
                {"name", safe_string(bytes.subspan(version2 ? 16 : 8, version2 ? 128 : 32))},
                {"steam_id", std::to_string(big_endian(bytes.subspan(version2 ? 8 : 0, 8)))},
                {"user_id", big_endian(bytes.subspan(version2 ? 144 : 40, 4))}};
            const unsigned bot_offset = version2 ? 316 : 116;
            if (data.size() > bot_offset) info["bot"] = data[bot_offset] != 0;
            users[static_cast<int>(index) + 1] = std::move(info);
        }
    }
    void update_strings(Strings& strings, const Bytes& bytes, unsigned count) {
        require(count <= strings.maximum && bytes.size() <= 524284, "String table update exceeds bounds");
        BitReader in(bytes);
        const bool encoded_dictionary = in.bit();
        int last = -1, last_dictionary = -1;
        std::deque<std::string> history;
        for (unsigned i = 0; i < count; ++i) {
            const auto index = in.bit() ? static_cast<unsigned>(last + 1) : in.bits(strings.entry_bits);
            require(index < strings.maximum && index <= strings.entries.size(), "Invalid string table entry index");
            last = static_cast<int>(index);
            std::string name;
            const bool has_name = in.bit();
            if (has_name) {
                if (encoded_dictionary && in.bit()) {
                    require(!dictionary.empty(), "Missing map string-table dictionary metadata");
                    last_dictionary = in.bit() ? last_dictionary + 1 : static_cast<int>(in.bits(dictionary_bits));
                    require(last_dictionary >= 0 && static_cast<std::size_t>(last_dictionary) < dictionary.size(), "Invalid map dictionary index");
                    name = dictionary[last_dictionary];
                } else if (in.bit()) {
                    const auto previous = in.bits(5), prefix = in.bits(5);
                    require(previous < history.size() && prefix <= history[previous].size(), "Invalid string-table history reference");
                    name = history[previous].substr(0, prefix) + in.string(1024);
                } else name = in.string(1024);
            }
            Bytes data;
            if (in.bit()) {
                if (strings.fixed) data = in.bit_bytes(strings.data_bits);
                else data = in.bytes(in.bits(14));
            }
            if (index < strings.entries.size()) {
                require(!has_name || name == strings.entries[index].name, "Server changed an existing string-table key");
                strings.entries[index].data = std::move(data);
                name = strings.entries[index].name;
            } else {
                require(has_name, "New string-table entry has no name");
                strings.entries.push_back({name, std::move(data)});
            }
            if (history.size() == 32) history.pop_front();
            history.push_back(name.substr(0, 31));
        }
    }
    bool packet_entities(const Proto& message) {
        const bool delta = message.get_u32(3) != 0, update = message.get_u32(4) != 0;
        const auto baseline = message.get_u32(5);
        const auto count = message.get_u32(2), maximum = message.get_u32(1, 2048);
        require(baseline < 2 && maximum <= 2048 && count <= maximum, "Invalid entity packet bounds");
        const auto from = message.get_i32(6, -1);
        if (delta && (from == tick || !frames.contains(from))) {
            full_update = true;
            event({{"type", "snapshot_recovery"}, {"delta_from", from}, {"reason", "Missing snapshot history"}});
            return false;
        }
        require(!classes.empty(), "No exact entity schema loaded");
        Entities next = delta ? frames.at(from) : Entities{};
        Entities live = delta ? current : Entities{};
        auto next_baselines = delta ? baselines : std::array<Entities, 2>{};
        if (update) next_baselines[1 - baseline] = next_baselines[baseline];
        const auto bytes = message.get_bytes(7);
        require(bytes.size() <= 524284, "Entity bitstream too large");
        BitReader in(bytes);
        int index = -1;
        for (unsigned i = 0; i < count; ++i) {
            const auto skip = in.ubitvar();
            require(skip < maximum && static_cast<std::uint64_t>(index + 1) + skip < maximum, "Entity index exceeds packet bounds");
            index += static_cast<int>(skip) + 1;
            const bool leave = in.bit(), second = in.bit();
            if (leave) {
                require(delta && next.contains(index), "Leave-PVS refers to a missing entity");
                next.erase(index);
                if (second) live.erase(index);
                continue;
            }
            std::shared_ptr<Entity> entity;
            if (second) {
                const auto class_id = static_cast<int>(in.bits(class_bits));
                const auto serial = static_cast<int>(in.bits(10));
                require(classes.contains(class_id), "Entity uses an unknown server class");
                entity = std::make_shared<Entity>();
                entity->index = index; entity->class_id = class_id; entity->serial = serial;
                const auto found = next_baselines[baseline].find(index);
                if (delta && found != next_baselines[baseline].end() && found->second->class_id == class_id)
                    entity->fields = found->second->fields;
                else {
                    const auto base = class_baselines.find(class_id);
                    require(base != class_baselines.end(), "Missing static baseline for class " + classes.at(class_id).name);
                    BitReader baseline_reader(base->second);
                    decode_fields(baseline_reader, classes.at(class_id), entity->fields);
                }
            } else {
                const auto previous = next.find(index);
                require(delta && previous != next.end(), "Entity delta refers to a missing entity");
                entity = std::make_shared<Entity>(*previous->second);
            }
            decode_fields(in, classes.at(entity->class_id), entity->fields);
            next[index] = entity;
            live[index] = entity;
            if (update && second) next_baselines[1 - baseline][index] = entity;
        }
        if (delta) {
            const auto deletes = in.ubitvar();
            require(deletes <= 2048, "Deletion count exceeds entity limit");
            int base = -1;
            for (unsigned i = 0; i < deletes; ++i) {
                const auto skip = in.ubitvar();
                require(skip <= 2048 && static_cast<std::int64_t>(base) + skip >= 0 &&
                        static_cast<std::int64_t>(base) + skip < 2048, "Invalid explicit entity deletion");
                base += static_cast<int>(skip);
                require(!next.contains(base), "Explicit deletion refers to an entity still in PVS");
                live.erase(base);
            }
        }
        // A delta can refer to an older acknowledged frame. Unchanged entities
        // must inherit that frame too, including reversions since a later frame.
        for (const auto& [slot, entity] : next) live[slot] = entity;
        current = std::move(live); baselines = std::move(next_baselines);
        if (!delta) frames.clear();
        frames[tick] = std::move(next);
        while (frames.size() > 64) frames.erase(frames.begin());
        snapshot_tick = tick; full_update = false;
        if (update) {
            ProtoWriter ack;
            ack.i32(1, tick).u32(2, baseline);
            outgoing.emplace_back(11, Proto(ack.data()));
        }
        return true;
    }
    void event_list(const Proto& message) {
        std::map<int, EventDescriptor> next;
        for (const auto& descriptor : message.get_messages(1)) {
            const auto id = descriptor.get_i32(1);
            require(id >= 0 && id < 1024 && !next.contains(id), "Invalid game event descriptor ID");
            EventDescriptor item;
            item.name = descriptor.get_string(2);
            for (const auto& key : descriptor.get_messages(3)) item.keys.emplace_back(key.get_i32(1), key.get_string(2));
            next.emplace(id, std::move(item));
        }
        descriptors = std::move(next);
        ProtoWriter listen;
        std::array<std::uint32_t, 16> mask{};
        for (const auto& [id, ignored] : descriptors) if (id < 512) mask[id / 32] |= 1u << (id % 32);
        for (auto value : mask) listen.fixed32(1, value);
        outgoing.emplace_back(12, Proto(listen.data()));
    }
    void game_event(const Proto& message) {
        const int id = message.get_i32(2);
        const auto descriptor = descriptors.find(id);
        const auto name = descriptor == descriptors.end() ? message.get_string(1) : descriptor->second.name;
        Json values = Json::object();
        const auto keys = message.get_messages(3);
        for (std::size_t i = 0; i < keys.size(); ++i) {
            const auto& key = keys[i];
            std::string key_name = "key_" + std::to_string(i);
            if (descriptor != descriptors.end() && i < descriptor->second.keys.size()) key_name = descriptor->second.keys[i].second;
            switch (key.get_u32(1)) {
            case 1: values[key_name] = key.get_string(2); break;
            case 2: values[key_name] = key.get_float(3); break;
            case 3: values[key_name] = key.get_i32(4); break;
            case 4: values[key_name] = key.get_i32(5); break;
            case 5: values[key_name] = key.get_u32(6); break;
            case 6: values[key_name] = key.get_u32(7) != 0; break;
            case 7: values[key_name] = std::to_string(key.get_u64(8)); break;
            default: values[key_name] = opaque_fields(key); break;
            }
        }
        if (name == "round_start") round = {{"phase", "active"}, {"start_tick", tick}, {"details", values}};
        else if (name == "round_end") { round["phase"] = "ended"; round["end_tick"] = tick; round["result"] = values; }
        else if (name == "round_freeze_end") { round["phase"] = "active"; round["freeze_end_tick"] = tick; }
        else if (name == "round_prestart") round["phase"] = "freeze";
        event({{"type", "game_event"}, {"name", name}, {"event_id", id}, {"values", values}});
    }
    Json entity_status(const Entity& entity, bool active) const {
        Json result{{"entity_index", entity.index}, {"class", classes.at(entity.class_id).name},
            {"serial", entity.serial}, {"in_pvs", active}, {"fields", entity.fields}};
        if (users.contains(entity.index)) result.update(users.at(entity.index));
        for (const auto& [source, target] : std::initializer_list<std::pair<const char*, const char*>>{
                {"m_iHealth", "health"}, {"m_ArmorValue", "armor"}, {"m_iAccount", "money"},
                {"m_iTeamNum", "team"}, {"m_lifeState", "life_state"}, {"m_bHasHelmet", "helmet"},
                {"m_bHasDefuser", "defuser"}, {"m_hActiveWeapon", "active_weapon_handle"}})
            if (const auto* value = suffix(entity.fields, source)) result[target] = *value;
        Json position = Json::array({nullptr, nullptr, nullptr});
        const std::string preferred = entity.index == player_slot + 1 ? "cslocaldata." : "csnonlocaldata.";
        auto origin = [&](const std::string& name) {
            if (const auto* value = suffix(entity.fields, preferred + name)) return value;
            return suffix(entity.fields, name);
        };
        if (const auto* value = origin("m_vecOrigin")) {
            if (value->is_array()) for (std::size_t i = 0; i < std::min(std::size_t{3}, value->size()); ++i) position[i] = (*value)[i];
        }
        for (std::size_t i = 0; i < 3; ++i)
            if (const auto* value = origin("m_vecOrigin[" + std::to_string(i) + "]")) position[i] = *value;
        result["position"] = std::move(position);
        Json inventory = Json::array();
        std::set<int> weapon_indices;
        auto add_weapon = [&](const Json& value) {
            if (!value.is_number_integer() && !value.is_number_unsigned()) return;
            const auto handle = value.get<std::uint32_t>();
            if (handle == 0xffffffffu || handle == 0x1fffffu) return;
            const auto index = static_cast<int>(handle & 2047u);
            if (!index || !weapon_indices.insert(index).second) return;
            Json weapon{{"entity_index", index}, {"handle", handle}};
            const auto item = current.find(index);
            if (item != current.end() && (handle >> 11) == static_cast<std::uint32_t>(item->second->serial)) {
                weapon["class"] = classes.at(item->second->class_id).name;
                if (const auto* definition = suffix(item->second->fields, "m_iItemDefinitionIndex")) weapon["item_definition"] = *definition;
                if (const auto* clip = suffix(item->second->fields, "m_iClip1")) weapon["clip"] = *clip;
            }
            inventory.push_back(std::move(weapon));
        };
        for (auto field = entity.fields.begin(); field != entity.fields.end(); ++field) {
            if (field.key().find("m_hMyWeapons") == std::string::npos) continue;
            if (field.value().is_array()) for (const auto& value : field.value()) add_weapon(value);
            else add_weapon(field.value());
        }
        result["inventory"] = std::move(inventory);
        return result;
    }
};

State::State() : impl_(std::make_unique<Impl>()) {}
State::~State() = default;
State::State(State&&) noexcept = default;
State& State::operator=(State&&) noexcept = default;

void State::load_profile(const Json& profile) {
    auto next = std::make_unique<Impl>();
    const auto& schema = profile.contains("entity_schema") ? profile.at("entity_schema") : profile;
    for (const auto& value : schema.at("send_tables")) {
        auto table = table_from_json(value);
        require(!next->tables.contains(table.name), "Duplicate send table in metadata");
        next->tables.emplace(table.name, std::move(table));
    }
    for (const auto& value : schema.at("classes")) {
        Class cls;
        cls.id = value.at("id").get<int>(); cls.name = value.at("name").get<std::string>(); cls.table = value.at("table").get<std::string>();
        require(cls.id >= 0 && cls.id < 1024 && !next->classes.contains(cls.id), "Invalid or duplicate class identifier");
        next->classes.emplace(cls.id, std::move(cls));
    }
    next->dictionary = schema.value("dictionary", std::vector<std::string>{});
    require(next->dictionary.size() <= 65536, "Map string dictionary exceeds limit");
    next->dictionary_bits = schema.value("dictionary_bits", width(static_cast<unsigned>(next->dictionary.size())));
    require(next->dictionary_bits <= 16, "Map dictionary width exceeds limit");
    next->rebuild();
    impl_ = std::move(next);
}
void State::reset() { impl_->clear(); }
void State::set_server_info(std::string map, std::int32_t slot, std::int32_t maximum, float interval) {
    require(slot >= 0 && maximum >= 1 && maximum <= 64 && slot < maximum && std::isfinite(interval) && interval > 0 && interval < 1,
            "Invalid server info");
    if (!impl_->map.empty() && impl_->map != map) impl_->clear();
    impl_->map = std::move(map); impl_->player_slot = slot; impl_->max_clients = maximum; impl_->interval = interval;
}
bool State::consume(std::uint32_t type, const Proto& message, std::int32_t tick) {
    impl_->tick = tick;
    try {
        switch (type) {
        case 8:
            set_server_info(message.get_string(16), message.get_i32(13), message.get_i32(11), message.get_float(14));
            impl_->tick = tick;
            return true;
        case 9:
            if (!message.get_u32(1)) {
                auto table = table_from_proto(message);
                impl_->tables[table.name] = std::move(table);
            } else impl_->rebuild();
            return true;
        case 10:
            if (!message.get_u32(1)) {
                std::map<int, Class> classes;
                for (const auto& item : message.get_messages(2)) {
                    Class cls;
                    cls.id = item.get_i32(1); cls.table = item.get_string(2); cls.name = item.get_string(3);
                    require(cls.id >= 0 && cls.id < 1024 && !classes.contains(cls.id), "Invalid class info");
                    classes.emplace(cls.id, std::move(cls));
                }
                impl_->classes = std::move(classes);
            }
            impl_->rebuild();
            require(!impl_->classes.empty(), "Server requests client-created classes but exact schema is unavailable");
            return true;
        case 12: {
            require(impl_->string_tables.size() < 32, "Too many string tables");
            Impl::Strings strings;
            strings.name = message.get_string(1); strings.maximum = message.get_u32(2);
            require(strings.maximum > 0 && strings.maximum <= 65536 && std::has_single_bit(strings.maximum), "String-table capacity must be a power of two");
            strings.entry_bits = std::bit_width(strings.maximum) - 1;
            strings.fixed = message.get_u32(4) != 0; strings.data_size = message.get_u32(5); strings.data_bits = message.get_u32(6);
            require(strings.data_size <= 16384 && strings.data_bits <= strings.data_size * 8 && strings.data_bits <= 16384 * 8,
                    "Fixed string-table userdata exceeds bounds");
            auto bytes = message.get_bytes(8);
            // The 2019 schema has no compressed-string fields. Some later
            // versions carry a Valve LZSS envelope; decode that signature only.
            if (bytes.size() >= 4 && std::string(bytes.begin(), bytes.begin() + 4) == "LZSS") bytes = lzss_decompress(bytes);
            impl_->update_strings(strings, bytes, message.get_u32(3));
            impl_->string_tables.push_back(std::move(strings));
            const auto& added = impl_->string_tables.back();
            for (unsigned i = 0; i < added.entries.size(); ++i) impl_->user(added, i);
            return true;
        }
        case 13: {
            const auto id = message.get_u32(1);
            require(id < impl_->string_tables.size(), "Update refers to an unknown string table");
            auto strings = impl_->string_tables[id];
            impl_->update_strings(strings, message.get_bytes(3), message.get_u32(2, 1));
            impl_->string_tables[id] = std::move(strings);
            const auto& updated = impl_->string_tables[id];
            for (unsigned i = 0; i < updated.entries.size(); ++i) impl_->user(updated, i);
            return true;
        }
        case 23: {
            const auto subtype = message.get_u32(1);
            const auto data = message.get_bytes(2);
            const Proto body(data);
            Json value{{"type", "user_message"}, {"message_type", subtype}, {"fields", opaque_fields(body)}};
            if (subtype == 5 || subtype == 6) { value["entity_index"] = body.get_u32(1); value["text"] = body.get_string(subtype == 5 ? 2 : 3); }
            else if (subtype == 7 || subtype == 23) {
                Json text = Json::array();
                for (const auto& field : body.fields(subtype == 7 ? 2 : 1)) text.push_back(std::string(field.data.begin(), field.data.end()));
                value["text"] = std::move(text);
            }
            impl_->event(std::move(value));
            return true;
        }
        case 25: impl_->game_event(message); return true;
        case 26: return impl_->packet_entities(message);
        case 30: impl_->event_list(message); return true;
        default: return false;
        }
    } catch (const StateError&) { throw; }
    catch (const std::exception& error) { throw StateError(std::string("Malformed state message: ") + error.what()); }
}
Json State::status() const {
    Json players = Json::array(), local;
    const auto frame = impl_->frames.find(impl_->snapshot_tick);
    for (const auto& [index, entity] : impl_->current) {
        if (index < 1 || index > impl_->max_clients || impl_->classes.at(entity->class_id).name.find("Player") == std::string::npos) continue;
        const bool active = frame != impl_->frames.end() && frame->second.contains(index);
        auto value = impl_->entity_status(*entity, active);
        if (index == impl_->player_slot + 1) local = value;
        players.push_back(std::move(value));
    }
    Json round = impl_->round;
    for (const auto& [index, entity] : impl_->current) {
        if (impl_->classes.at(entity->class_id).name != "CCSGameRulesProxy") continue;
        for (const auto& [source, target] : std::initializer_list<std::pair<const char*, const char*>>{
            {"m_bFreezePeriod", "freeze"}, {"m_bWarmupPeriod", "warmup"}, {"m_totalRoundsPlayed", "rounds_played"},
            {"m_fRoundStartTime", "start_time"}, {"m_iRoundTime", "round_time"}})
            if (const auto* value = suffix(entity->fields, source)) round[target] = *value;
    }
    return {{"map", impl_->map}, {"tick", impl_->tick}, {"entity_tick", impl_->snapshot_tick},
        {"tick_interval", impl_->interval}, {"local", local}, {"players", players}, {"round", round},
        {"entity_count", impl_->current.size()}, {"string_table_count", impl_->string_tables.size()},
        {"needs_full_update", impl_->full_update}};
}
std::vector<Json> State::take_events() {
    std::vector<Json> result;
    while (!impl_->events.empty()) { result.push_back(std::move(impl_->events.front())); impl_->events.pop_front(); }
    return result;
}
std::vector<std::pair<std::uint32_t, Proto>> State::take_outgoing() { auto result = std::move(impl_->outgoing); impl_->outgoing.clear(); return result; }
bool State::needs_full_update() const { return impl_->full_update; }
void State::clear_full_update_request() { impl_->full_update = false; }
std::int32_t State::entity_tick() const { return impl_->snapshot_tick; }
std::size_t State::class_count() const { return impl_->classes.size(); }

} // namespace hc
