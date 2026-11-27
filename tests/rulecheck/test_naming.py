"""New groups and target lists are numbered like yours (D-1091): the next G and T number.
Run: python tests/rulecheck/test_naming.py app"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stubs  # noqa: E402

stubs.install(sys.argv[1] if len(sys.argv) > 1 else "app")
import access  # noqa: E402

fails, checks = [], 0


def check(name, got, want):
    global checks
    checks += 1
    if got != want:
        fails.append(f"{name}: got {got!r}, want {want!r}")


groups = {str(i): {"name": n} for i, n in enumerate(
    ["G01 Guests", "G02 NAS .5", "G09 Cameras .10", "G24 Air Conditioners .20", "G29 NAS Recovery .5", "Quarantine"])}
check("next G number", access.howto_group_number(groups), "G30 ")
check("Quarantine and unnumbered groups don't stop it", access.howto_group_number({**groups, "x": {"name": "Kids"}}), "G30 ")
check("mostly unnumbered: no number", access.howto_group_number({"1": {"name": "Kids"}, "2": {"name": "TVs"}, "3": {"name": "G01 Guests"}}), "")
check("no groups: no number", access.howto_group_number({}), "")
check("group name with number and network", access.howto_fit([access.howto_short_name("Air Conditioner 2 .20") + " .20"], prefix="G30 "),
      "G30 Air Conditioner 2 .20")
check("long name fits in 32", len(access.howto_fit([access.howto_short_name("A Very Long Client Name For Testing Fit") + " .20"], prefix="G30 ")) <= 32, True)
access.msp["lists"] = {str(i): {"name": n} for i, n in enumerate(["T01 Cameras", "T08 NAS PC 1", "T11 NAS Recovery PC 2", "dap_x"])}
check("next T number", access.howto_list_number(), "T12 ")
check("T number counts lists this plan already named", access.howto_list_number(["T12 Printer"]), "T13 ")
print("\n".join(fails) or f"all {checks} pass")
sys.exit(1 if fails else 0)
