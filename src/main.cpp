// hashguard: lightweight File Integrity Monitor (FIM) with built-in SHA-256.
// Detects added / modified / deleted files against a trusted baseline and flags
// suspicious changes (possible webshells, new executables, edited system configs).
// Author: Martin Ivanov (Martun1) | License: MIT | C++17
#include "sha256.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;
using hg::SHA256;

namespace col {
bool on = true;
const char* c(const char* s) { return on ? s : ""; }
}  // namespace col
#define RST col::c("\033[0m")
#define BLD col::c("\033[1m")
#define DIM col::c("\033[2m")
#define RED col::c("\033[91m")
#define GRN col::c("\033[92m")
#define YEL col::c("\033[93m")
#define BLU col::c("\033[94m")
#define MAG col::c("\033[95m")
#define CYN col::c("\033[96m")

static const char* VERSION = "1.0.0";
static const char* DEFAULT_DB = ".hashguard.db";

struct Entry {
    std::string hash;
    uintmax_t size = 0;
};
using Baseline = std::map<std::string, Entry>;  // relative path -> entry (sorted)

struct Options {
    std::string db = DEFAULT_DB;
    std::vector<std::string> excludes = {".git", "node_modules", "__pycache__", ".hashguard.db"};
    int interval = 5;
    bool json = false;
};

// --------------------------------------------------------------------- utils
static std::string now_str() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

static bool excluded(const fs::path& rel, const Options& o) {
    for (auto& part : rel)
        for (auto& ex : o.excludes)
            if (part.string() == ex) return true;
    return false;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) { return (char)std::tolower(ch); });
    return s;
}

static Baseline scan(const fs::path& root, const Options& o, size_t* bytes = nullptr) {
    Baseline b;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        fs::path rel = fs::relative(it->path(), root, ec);
        if (excluded(rel, o)) {
            if (it->is_directory(ec)) it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file(ec)) continue;
        Entry e;
        e.size = it->file_size(ec);
        e.hash = SHA256::file(it->path().string());
        if (bytes) *bytes += e.size;
        b[rel.generic_string()] = e;
    }
    return b;
}

static void save(const fs::path& file, const fs::path& root, const Baseline& b) {
    std::ofstream out(file);
    out << "# hashguard baseline v1\n# root: " << fs::absolute(root).generic_string() << "\n# created: " << now_str()
        << "\n# files: " << b.size() << "\n";
    for (auto& [path, e] : b) out << e.hash << "  " << e.size << "  " << path << "\n";
}

static Baseline load(const fs::path& file) {
    std::ifstream in(file);
    if (!in) throw std::runtime_error("no baseline found at '" + file.string() + "'. Run 'hashguard init' first.");
    Baseline b;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream is(line);
        Entry e;
        is >> e.hash >> e.size;
        is.ignore(2);
        std::string path;
        std::getline(is, path);
        b[path] = e;
    }
    return b;
}

// --------------------------------------------------------------------- risk
struct Change {
    char kind;  // A, M, D
    std::string path;
    std::string risk;    // CRITICAL/HIGH/MEDIUM/LOW
    std::string reason;
};

static const std::set<std::string> EXEC_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".elf", ".so", ".scr"};
static const std::set<std::string> WEB_EXT = {".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx"};
static const std::vector<std::string> SENSITIVE = {"passwd", "shadow", "sudoers", "authorized_keys", "crontab",
                                                   ".htaccess", "web.config", "hosts", "sshd_config", ".bashrc"};
static const std::vector<std::string> WEBSHELL_SIGS = {"eval(", "base64_decode(", "shell_exec(", "system($_", "passthru(",
                                                      "assert($_", "cmd.exe", "/bin/sh", "Runtime.getRuntime"};

static std::pair<std::string, std::string> assess(const fs::path& root, const std::string& rel, char kind) {
    fs::path p(rel);
    std::string ext = lower(p.extension().string()), name = lower(p.filename().string());
    if (kind != 'D' && WEB_EXT.count(ext)) {
        std::ifstream in(root / p, std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(in)), {});
        for (auto& sig : WEBSHELL_SIGS)
            if (body.find(sig) != std::string::npos)
                return {"CRITICAL", "possible webshell: contains '" + sig + "'"};
        if (kind == 'A') return {"HIGH", "new server-side script"};
    }
    for (auto& s : SENSITIVE)
        if (name == s) return {"HIGH", "security-sensitive file " + std::string(kind == 'D' ? "deleted" : "changed")};
    if (kind == 'A' && EXEC_EXT.count(ext)) return {"HIGH", "new executable/script"};
    if (ext == ".log" && kind == 'D') return {"HIGH", "log file deleted (covering tracks?)"};
    if (ext == ".log" || ext == ".tmp" || ext == ".cache") return {"LOW", "volatile file"};
    if (kind == 'D') return {"MEDIUM", "file removed"};
    return {"MEDIUM", kind == 'A' ? "new file" : "content changed"};
}

static std::vector<Change> diff(const fs::path& root, const Baseline& base, const Baseline& cur) {
    std::vector<Change> out;
    for (auto& [p, e] : cur) {
        auto it = base.find(p);
        if (it == base.end()) out.push_back({'A', p, "", ""});
        else if (it->second.hash != e.hash) out.push_back({'M', p, "", ""});
    }
    for (auto& [p, e] : base)
        if (!cur.count(p)) out.push_back({'D', p, "", ""});
    static const std::map<std::string, int> rank = {{"CRITICAL", 0}, {"HIGH", 1}, {"MEDIUM", 2}, {"LOW", 3}};
    for (auto& c : out) std::tie(c.risk, c.reason) = assess(root, c.path, c.kind);
    std::stable_sort(out.begin(), out.end(), [](auto& a, auto& b) { return rank.at(a.risk) < rank.at(b.risk); });
    return out;
}

static const char* risk_color(const std::string& r) {
    return r == "CRITICAL" ? MAG : r == "HIGH" ? RED : r == "MEDIUM" ? YEL : BLU;
}

static void print_changes(const std::vector<Change>& ch) {
    for (auto& c : ch) {
        const char* kc = c.kind == 'A' ? GRN : c.kind == 'M' ? YEL : RED;
        const char* label = c.kind == 'A' ? "ADDED   " : c.kind == 'M' ? "MODIFIED" : "DELETED ";
        std::cout << "  " << kc << BLD << label << RST << "  " << risk_color(c.risk) << c.risk
                  << std::string(9 - c.risk.size(), ' ') << RST << c.path << DIM << "  ← " << c.reason << RST << "\n";
    }
}

static std::string json_escape(const std::string& s) {
    std::string o;
    for (char ch : s) {
        if (ch == '"' || ch == '\\') o += '\\';
        o += ch;
    }
    return o;
}

static void print_json(const std::vector<Change>& ch) {
    std::cout << "[\n";
    for (size_t i = 0; i < ch.size(); ++i)
        std::cout << "  {\"change\":\"" << ch[i].kind << "\",\"path\":\"" << json_escape(ch[i].path) << "\",\"risk\":\""
                  << ch[i].risk << "\",\"reason\":\"" << json_escape(ch[i].reason) << "\"}" << (i + 1 < ch.size() ? "," : "")
                  << "\n";
    std::cout << "]\n";
}

static void header(const std::string& what) {
    std::cout << "\n  " << BLD << CYN << "⛨ hashguard v" << VERSION << RST << DIM << "  " << what << RST << "\n\n";
}

// --------------------------------------------------------------------- commands
static fs::path db_path(const fs::path& root, const Options& o) {
    fs::path d(o.db);
    return d.is_absolute() ? d : root / d;
}

static int cmd_init(const fs::path& root, const Options& o) {
    header("creating baseline for " + root.generic_string());
    auto t0 = std::chrono::steady_clock::now();
    size_t bytes = 0;
    auto b = scan(root, o, &bytes);
    save(db_path(root, o), root, b);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    std::cout << "  " << GRN << "✔" << RST << " hashed " << BLD << b.size() << RST << " files (" << bytes / 1024
              << " KiB) in " << (int)ms << " ms\n  " << GRN << "✔" << RST << " baseline saved → " << db_path(root, o).generic_string()
              << "\n  " << DIM << "tip: store a copy of the baseline offline. An attacker with write access could edit it."
              << RST << "\n\n";
    return 0;
}

static int cmd_check(const fs::path& root, const Options& o) {
    auto base = load(db_path(root, o));
    auto cur = scan(root, o);
    auto ch = diff(root, base, cur);
    if (o.json) { print_json(ch); return ch.empty() ? 0 : 1; }
    header("integrity check of " + root.generic_string());
    if (ch.empty()) {
        std::cout << "  " << GRN << "✔ No changes." << RST << " " << cur.size() << " files match the baseline.\n\n";
        return 0;
    }
    print_changes(ch);
    int crit = (int)std::count_if(ch.begin(), ch.end(), [](auto& c) { return c.risk == "CRITICAL"; });
    int high = (int)std::count_if(ch.begin(), ch.end(), [](auto& c) { return c.risk == "HIGH"; });
    std::cout << "\n  " << BLD << ch.size() << " change(s)" << RST << "  ·  " << MAG << crit << " critical" << RST << "  ·  "
              << RED << high << " high" << RST << "  ·  " << cur.size() << " files scanned\n";
    if (crit) std::cout << "  " << MAG << BLD << "⚠ Investigate CRITICAL items immediately (possible compromise)." << RST << "\n";
    std::cout << "\n";
    return crit ? 2 : 1;
}

static int cmd_watch(const fs::path& root, const Options& o, int max_rounds) {
    auto base = load(db_path(root, o));
    header("watching " + root.generic_string() + " every " + std::to_string(o.interval) + "s (Ctrl+C to stop)");
    std::set<std::string> reported;
    for (int round = 0; max_rounds <= 0 || round < max_rounds; ++round) {
        auto ch = diff(root, base, scan(root, o));
        for (auto& c : ch) {
            std::string key = std::string(1, c.kind) + c.path;
            if (reported.insert(key).second) {
                std::cout << "  " << DIM << "[" << now_str() << "]" << RST;
                print_changes({c});
            }
        }
        std::cout.flush();
        if (max_rounds <= 0 || round + 1 < max_rounds) std::this_thread::sleep_for(std::chrono::seconds(o.interval));
    }
    return 0;
}

static int cmd_accept(const fs::path& root, const Options& o) {
    auto base = load(db_path(root, o));
    auto cur = scan(root, o);
    auto ch = diff(root, base, cur);
    save(db_path(root, o), root, cur);
    header("baseline updated");
    std::cout << "  " << GRN << "✔" << RST << " accepted " << ch.size() << " change(s); baseline now has " << cur.size()
              << " files\n\n";
    return 0;
}

static void usage() {
    std::cout << "hashguard: file integrity monitor (SHA-256)\n\n"
                 "Usage:\n"
                 "  hashguard init   <dir>              create a trusted baseline\n"
                 "  hashguard check  <dir> [--json]     compare against the baseline (exit 0=clean 1=changes 2=critical)\n"
                 "  hashguard watch  <dir> [-i secs]    monitor continuously\n"
                 "  hashguard accept <dir>              approve current state as the new baseline\n"
                 "  hashguard hash   <file|-s text>     print the SHA-256 of a file or string\n\n"
                 "Options:\n"
                 "  --db <file>        baseline file (default: <dir>/.hashguard.db)\n"
                 "  --exclude <name>   skip files/folders with this name (repeatable)\n"
                 "  --no-color         disable colours\n";
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | 0x0004);
#endif
    Options o;
    std::vector<std::string> a;
    int rounds = 0;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--no-color") col::on = false;
        else if (s == "--json") o.json = true;
        else if (s == "--db" && i + 1 < argc) o.db = argv[++i];
        else if (s == "--exclude" && i + 1 < argc) o.excludes.push_back(argv[++i]);
        else if ((s == "-i" || s == "--interval") && i + 1 < argc) o.interval = std::max(1, std::stoi(argv[++i]));
        else if (s == "--rounds" && i + 1 < argc) rounds = std::stoi(argv[++i]);  // for demos/tests
        else a.push_back(s);
    }
    if (a.size() < 2) { usage(); return a.empty() ? 1 : 0; }
    try {
        const std::string& cmd = a[0];
        if (cmd == "hash") {
            if (a[1] == "-s" && a.size() > 2) std::cout << SHA256::of(a[2]) << "  \"" << a[2] << "\"\n";
            else {
                std::string d = SHA256::file(a[1]);
                if (d.empty()) throw std::runtime_error("cannot read " + a[1]);
                std::cout << d << "  " << a[1] << "\n";
            }
            return 0;
        }
        fs::path root(a[1]);
        if (!fs::is_directory(root)) throw std::runtime_error("not a directory: " + a[1]);
        if (cmd == "init") return cmd_init(root, o);
        if (cmd == "check") return cmd_check(root, o);
        if (cmd == "watch") return cmd_watch(root, o, rounds);
        if (cmd == "accept") return cmd_accept(root, o);
        usage();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << RED << "error: " << RST << e.what() << "\n";
        return 3;
    }
}
