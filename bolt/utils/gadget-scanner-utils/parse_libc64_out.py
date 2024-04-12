import sys
import re
import datetime
import itertools


def split_per_lib(lines):
    lib2output = {}
    current_lib = None
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("/usr/lib64/"):
            # print("found lib {}".format(line))
            current_lib = line
            assert current_lib not in lib2output, current_lib
            lib2output[current_lib] = []
        if current_lib is None:
            continue
        lib2output[current_lib].append(line)
    return lib2output


def discard_directories(lib2output):
    res = {}
    for lib in lib2output.keys():
        dir_line = "gadget-scanner: '{}': Is a directory.".format(lib)
        if dir_line in lib2output[lib]:
            continue
        res[lib] = lib2output[lib]
    return res


def filter_crashes(lib2output):
    res = {}
    no_crashing_libs = set()
    for lib in lib2output.keys():
        found_crash = False
        for line in lib2output[lib]:
            if line.startswith("PLEASE submit a bug report to "):
                found_crash = True
                # print("Found crash in {}. Line:{}. lib2output[lib]=\n{}".format(
                #    lib, line, "\n".join(lib2output[lib])))
                break
        if found_crash:
            res[lib] = lib2output[lib]
        else:
            no_crashing_libs.add(lib)
    return res, no_crashing_libs


bt_re1 = re.compile("^ *#[0-9]+ (0x[0-9a-f]+).*")
bt_re2 = re.compile("^ *[0-9]+ +[^ ]+ (0x[0-9a-f]+)")


def find_unique_backtraces(lib2output_crashes):
    backtrace2lib = {}
    for lib in lib2output_crashes.keys():
        bt_lines = []
        first_crash_line = None
        for i, line in enumerate(lib2output_crashes[lib]):
            # remove address as ASLR randomizes them
            if m := bt_re1.match(line):
                bt_lines.append(line[0 : m.start(1)] + line[m.end(1) : -1])
                if first_crash_line is None:
                    first_crash_line = i
            if m := bt_re2.match(line):
                bt_lines.append(line[0 : m.start(1)] + line[m.end(1) : -1])
                if first_crash_line is None:
                    first_crash_line = i
        assert len(bt_lines) > 0, lib
        # now add all lines that don't start with "BOLT" before the stack trace to the
        # front to have a bit more context
        assert first_crash_line is not None
        for i in range(first_crash_line - 1, 0, -1):
            line = lib2output_crashes[lib][i]
            if line.startswith("BOLT"):
                break
            bt_lines.insert(0, line)
        bt_lines = "\n".join(bt_lines)
        if bt_lines not in backtrace2lib:
            backtrace2lib[bt_lines] = []
        backtrace2lib[bt_lines].append(lib)
    return backtrace2lib


def print_backtraces(backtrace2lib):
    for i, bt in enumerate(backtrace2lib.keys()):
        print("Backtrace {}:\n{}\n".format(i, bt))
        print(
            " on {} inputs: {}".format(
                len(backtrace2lib[bt]), ", ".join(backtrace2lib[bt])
            )
        )


def compute_exec_time(lib2output):
    res = {}
    # Thu Mar 14 12:46:52 CET 2024
    format = "%a %b %d %H:%M:%S %p %Z %Y"
    for lib in lib2output.keys():
        start_time_txt = lib2output[lib][1]
        end_time_txt = lib2output[lib][-1]
        start_time = datetime.datetime.strptime(start_time_txt, format)
        end_time = datetime.datetime.strptime(end_time_txt, format)
        timedelta = end_time - start_time
        # print("Exec time for {}: {}".format(lib, timedelta))
        res[lib] = timedelta
    return res


def parse_nr_instructions(nr_instructions_lines, lib2output):
    res = {}
    for lib, nr_instructions in itertools.batched(nr_instructions_lines, 2):
        lib = lib.strip()
        if lib not in lib2output:
            continue
        res[lib] = int(nr_instructions)
    return res


def discard_no_nr_instructions(lib2output, lib2nr_instructions):
    res = {}
    for lib in lib2output.keys():
        output = lib2output[lib]
        if lib not in lib2nr_instructions:
            # print("lib {} not found nr_instructions".format(lib))
            continue
        res[lib] = output
    return res


def compute_nr_instructions_per_second(
    lib2exec_time, lib2nr_instructions, no_crashing_libs
):
    total_instr = 0
    total_time = 0
    nr_libs = 0
    # print("lib2nr_instructions: {}".format(lib2nr_instructions))
    for lib in lib2nr_instructions.keys():
        td = lib2exec_time[lib]
        if lib not in no_crashing_libs:
            print("lib {} crashed, not keeping".format(lib))
            continue
        # if lib not in lib2nr_instructions:
        #    print("lib {} not found nr_instructions".format(lib))
        #    continue
        exec_time_seconds = td.seconds + td.microseconds * 1e-6 + td.days * 24 * 3600
        total_time += exec_time_seconds
        total_instr += lib2nr_instructions[lib]
        nr_libs += 1
    print(
        "total instr: {}; total seconds: {}; {} libs total".format(
            total_instr, total_time, nr_libs
        )
    )
    return total_instr * 1.0 / total_time


def parse_pacret_gadget_reports(lib2output):
    res = {}
    for lib, output in lib2output.items():
        gadget_report = None
        reports = []
        for line in output:
            if line.startswith("GS-PACRET:"):
                gadget_report = [line]
            if gadget_report is not None:
                if line.startswith(" "):
                    gadget_report.append(line)
                else:
                    reports.append(gadget_report)
                    gadget_report = None
        if len(reports) != 0:
            res[lib] = reports
    return res


def parse_stackclash_gadget_reports(lib2output):
    res = {}
    for lib, output in lib2output.items():
        gadget_report = None
        reports = []
        for line in output:
            if line.startswith("GS-STACKCLASH:"):
                gadget_report = [line]
            if gadget_report is not None:
                if line.startswith(" "):
                    gadget_report.append(line)
                else:
                    reports.append(gadget_report)
                    gadget_report = None
        if len(reports) != 0:
            res[lib] = reports
    return res


def parse_pacretstats(lib2output):
    lib2nrCfgNonCfgRetInstr = {}
    re_stats = re.compile(
        "GS-PACRET-STATS: NrCFGFunctions=([0-9]+) NrNonCFGFunctions=([0-9]+) NrRets=([0-9]+) NrInstructions=([0-9]+)"
    )
    for lib, lines in lib2output.items():
        for line in lines:
            if m := re_stats.match(line.strip()):
                assert lib not in lib2nrCfgNonCfgRetInstr
                lib2nrCfgNonCfgRetInstr[lib] = (
                    int(m.group(1)),
                    int(m.group(2)),
                    int(m.group(3)),
                    int(m.group(4)),
                )
        # assert lib in lib2nrCfgNonCfgRetInstr
    return lib2nrCfgNonCfgRetInstr


def parse_stackclashstats(lib2output):
    lib2nrCfgNonCfgInstr = {}
    re_stats = re.compile(
        "GS-STACKCLASH-STATS: NrCFGFunctions=([0-9]+) NrNonCFGFunctions=([0-9]+) NrInstructions=([0-9]+)"
    )
    for lib, lines in lib2output.items():
        for line in lines:
            if m := re_stats.match(line.strip()):
                assert lib not in lib2nrCfgNonCfgInstr
                lib2nrCfgNonCfgInstr[lib] = (
                    int(m.group(1)),
                    int(m.group(2)),
                    int(m.group(3)),
                )
        # assert lib in lib2nrCfgNonCfgInstr
    return lib2nrCfgNonCfgInstr


def print_total_stats(lib2output, no_crashing_libs, lib2nrCfgNonCfgRetInstr):
    total_instrs = 0
    total_rets = 0
    total_cfg = 0
    total_noncfg = 0
    for lib in lib2output.keys():
        if lib not in no_crashing_libs:
            continue
        if lib not in lib2nrCfgNonCfgRetInstr:
            continue
        nrCfg, nrNonCfg, nrRet, nrInstr = lib2nrCfgNonCfgRetInstr[lib]
        total_instrs += nrInstr
        total_rets += nrRet
        total_cfg += nrCfg
        total_noncfg += nrNonCfg
    print(
        "Total instr: {}, returns: {}, cfg functions: {}, non-cfg functions: {}".format(
            total_instrs, total_rets, total_cfg, total_noncfg
        )
    )


def main():
    lib2output = split_per_lib(sys.stdin.readlines())
    print("Found {} libs".format(len(lib2output)))

    lib2output = discard_directories(lib2output)
    print("After discarding directories: {} libs left".format(len(lib2output)))

    lib2exec_time = compute_exec_time(lib2output)
    with open("nr_instructions_lib64.txt") as f:
        lines = f.readlines()
        lib2nr_instructions = parse_nr_instructions(lines, lib2output)

    lib2output = discard_no_nr_instructions(lib2output, lib2nr_instructions)
    print("After discarding no_nr_instructions: {} libs left".format(len(lib2output)))

    lib2output_crash, no_crashing_libs = filter_crashes(lib2output)
    print(
        "Found {} crashes: {}.\n{} without crashes".format(
            len(lib2output_crash),
            ", ".join(lib2output_crash.keys()),
            len(no_crashing_libs),
        )
    )
    backtrace2lib = find_unique_backtraces(lib2output_crash)
    print("Found {} unique backtraces among crashes".format(len(backtrace2lib)))
    print_backtraces(backtrace2lib)

    nr_instructions_per_second = compute_nr_instructions_per_second(
        lib2exec_time, lib2nr_instructions, no_crashing_libs
    )
    print("nr_instructions per second: {}".format(nr_instructions_per_second))

    # FIXME: print/create csv?

    # summarize gadgets found GS-PACRET/GS-STACKCLASH.
    lib2pacret_gadget = parse_pacret_gadget_reports(lib2output)
    print("Found {} libs with pacret gadgets".format(len(lib2pacret_gadget)))

    lib_pacret_gadget_sorted = sorted(
        lib2pacret_gadget.items(), key=lambda x: len(x[1]), reverse=True
    )
    lib2nrCfgNonCfgRetInstr = parse_pacretstats(lib2output)
    total_pacret_gadgets = 0
    for lib_pacretgadgets in lib_pacret_gadget_sorted:
        nrCfgNonCfgRetInstrRet = lib2nrCfgNonCfgRetInstr[lib_pacretgadgets[0]]
        total_pacret_gadgets += len(lib_pacretgadgets[1])
        print(
            "{}: {} pac-ret gadgets. {} rets, {} instrs, {} CFG functions, {} non-CFG functions".format(
                lib_pacretgadgets[0],
                len(lib_pacretgadgets[1]),
                nrCfgNonCfgRetInstrRet[2],
                nrCfgNonCfgRetInstrRet[3],
                nrCfgNonCfgRetInstrRet[0],
                nrCfgNonCfgRetInstrRet[1],
            )
        )
    print("Total nr of reported pacret gadgets: {}".format(total_pacret_gadgets))

    lib2stackclash_gadget = parse_stackclash_gadget_reports(lib2output)
    print("Found {} libs with stackclash gadgets".format(len(lib2stackclash_gadget)))
    lib_stackclash_gadget_sorted = sorted(
        lib2stackclash_gadget.items(), key=lambda x: len(x[1]), reverse=True
    )
    lib2nrCfgNonCfgInstr = parse_stackclashstats(lib2output)
    print("lib2nrCfgNonCfgInstr: {}".format(len(lib2nrCfgNonCfgInstr)))
    total_stackclash_gadgets = 0
    for lib_stackclashgadgets in lib_stackclash_gadget_sorted:
        print(lib_stackclashgadgets[0])
        nrCfgNonCfgRetInstrRet = lib2nrCfgNonCfgInstr[lib_stackclashgadgets[0]]
        total_stackclash_gadgets += len(lib_stackclashgadgets[1])
        print(
            "{}: {} stackclash gadgets. {} instrs, {} CFG functions, {} non-CFG functions".format(
                lib_stackclashgadgets[0],
                len(lib_stackclashgadgets[1]),
                nrCfgNonCfgRetInstrRet[2],
                nrCfgNonCfgRetInstrRet[0],
                nrCfgNonCfgRetInstrRet[1],
            )
        )
    print(
        "Total nr of reported stackclash gadgets: {}".format(total_stackclash_gadgets)
    )

    if len(lib2nrCfgNonCfgRetInstr) == 0:
        for lib in lib2nrCfgNonCfgInstr.keys():
            t = lib2nrCfgNonCfgInstr[lib]
            lib2nrCfgNonCfgRetInstr[lib] = (t[0], t[1], 0, t[2])
    print_total_stats(
        lib2output, no_crashing_libs, lib2nrCfgNonCfgRetInstr
    )



main()
