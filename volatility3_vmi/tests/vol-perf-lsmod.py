#!/usr/bin/env python3
import sys
import os
import gc

import logging
import time
import statistics

VMID = "one-1417"
# Note: For the vmifs experiments vmifs needs to be mounted in /mnt/${VMID}/
EXPERIMENTS = [
    # Experiment 0: Original Volatility, reading only stale data from cache, using vmifs
    ["NO", "/root/build/hr/volatility3-original/", "file:///mnt/" + VMID + "/mem"],
    # Experiment 1: Manually fixed Volatility (manual cache flush), reading fresh data in each iteration, using vmifs
    ["MANUAL", "/root/build/hr/volatility3-original/", "file:///mnt/" + VMID + "/mem"],
    # Experiment 2: Patched Volatility with inconsistent caches removed, using VMI direct access + VMIFresh
    ["NO", "/root/build/hr/volatility3", "vmi:///tmp/" + VMID + "/vmi-sock"],
]

ITERATIONS = 100
DELAY = 0.01

# DELAY 0.01:
# Exp0: => Average: 17.125 ms Median: 16.967 ms Stddev: 1.191 ms
# Exp1: => Average: 34.932 ms Median: 32.289 ms Stddev: 6.898 ms
# Exp2: => Average: 29.688 ms Median: 29.494 ms Stddev: 2.414 ms

# Note: This is somewhat sensitive to DELAY, for reasons not clear (for me)
# but the relative performance is very similar in each case
# DELAY 0.05:
# Exp0: => Average: 39.417 ms Median: 40.275 ms Stddev: 7.351 ms
# Exp1: => Average: 55.012 ms Median: 58.628 ms Stddev: 9.593 ms
# Exp2: => Average: 47.059 ms Median: 47.179 ms Stddev: 7.019 ms

# DELAY 0.1:
# Exp0: => Average: 49.856 ms Median: 53.012 ms Stddev: 8.868 ms
# Exp1: => Average: 62.908 ms Median: 64.153 ms Stddev: 9.417 ms
# Exp2: => Average: 61.755 ms Median: 63.677 ms Stddev: 7.769 ms

# DELAY 1.0, ITERATIONS=100
# Exp 0: => Average: 22.705 ms Median: 20.886 ms Stddev: 7.180 ms
# Exp 1: => Average: 55.707 ms Median: 63.781 ms Stddev: 15.375 ms
# Exp 2: => Average: 39.167 ms Median: 37.147 ms Stddev: 9.211 ms

exp = 0
if len(sys.argv) > 1:
    exp = int(sys.argv[1])
print("Running experiment ", exp)

VOLPATH = EXPERIMENTS[exp][1]
DUMPURL = EXPERIMENTS[exp][2]
DEFISFDIR = "/root/build/hr/volatility3/volatility3/symbols"

PLUGIN = "linux.lsmod.Lsmod"
# PLUGIN = "linux.mountinfo.MountInfo"
# PLUGIN = "linux.sockstat.Sockstat"
# PLUGIN = "linux.psaux.PsAux"

# We insert VOLPATH at the start of the python path, to make sure that the right Volatility version
# (original or modified) is used, as selected by the experiment
sys.path.insert(0, VOLPATH)
from volatility3 import framework  # noqa: E402
from volatility3 import symbols  # noqa: E402
from volatility3.framework import contexts  # noqa: E402
from volatility3.framework import automagic  # noqa: E402
from volatility3 import plugins  # noqa: E402
from volatility3.plugins import linux  # noqa: E402


def initvolplugin(dumpfile, plugin_name):
    # Initialize volatility framework
    framework.require_interface_version(2, 0, 0)
    # volatility3.framework.require_interface_version(1, 0, 0)
    # Create volatility context for the framework (stores important config)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = dumpfile

    # Add Linux plugins path to plugins path and validate
    plugins.__path__ = linux.__path__ + plugins.__path__
    _failures = framework.import_files(plugins, True)

    # Enable volatility logging (debug messages)
    logging.basicConfig()
    vollog = logging.getLogger()
    # vollog.setLevel(logging.DEBUG)

    symbols.__path__ = [DEFISFDIR] + symbols.__path__

    # Obtain an instance of the plugin
    aa = automagic.available(ctx)
    plugin_list = framework.list_plugins()
    ps = plugin_list[plugin_name]
    am = automagic.choose_automagic(aa, ps)
    print("")

    def progress(perc, comm):
        sys.stdout.write("\rProgress: %.1f%% " % perc + str(comm) + " " * 30)

    # Let automagic prepare the plugin
    _err = automagic.run(am, ctx, ps, "plugins", progress)
    pnam = "plugins." + plugin_name.rsplit('.')[-1]
    un = ps.unsatisfied(ctx, pnam)
    if un:
        print("\nUnsatisfied for ", plugin_name, un)
    return [ctx, ps(ctx, pnam, progress)]


def dummyvisitor(a, b):
    # print(a, b)
    pass


def measure(ctx, plugin_instance, clearcache):
    results = []
    for i in range(ITERATIONS+1):
        if clearcache == "MANUAL":
            # Re-open dump "file".
            # This will clear any Python-level caches as well as the vmifs buffer cache
            ml = ctx.layers["memory_layer"]
            ml.__init__(ml.context, ml.config_path, ml.name)
            vl = ctx.layers["layer_name"]
            vl.read.cache_clear()
            framework.clear_cache()

        gc.disable()
        start = time.perf_counter_ns()
        grid = plugin_instance.run()
        mid = time.perf_counter_ns()
        grid.populate(dummyvisitor, None)
        end = time.perf_counter_ns()
        gc.enable()
        print("iteration ", i, "run: %.3f ms" % ((mid - start) / 1000000),
              "populate: %.3f ms" % ((end - mid) / 1000000),
              "total: %.3f ms" % ((end - start) / 1000000))
        time.sleep(DELAY)
        results.append(end - mid)
    return results


if __name__ == '__main__':
    plugin = initvolplugin(DUMPURL, PLUGIN)
    data = measure(plugin[0], plugin[1], EXPERIMENTS[exp][0])

    print("ClearCache: ", EXPERIMENTS[exp][0], "Target:", DUMPURL, "Volatility:", VOLPATH,
          "LIBVMI:", os.environ.get('LD_LIBRARY_PATH'), "\n",
          "=> Average: %.3f ms" % (statistics.mean(data[1:]) / 1000000),
          "Median: %.3f ms" % (statistics.median(data[1:]) / 1000000),
          "Stddev: %.3f ms" % (statistics.stdev(data[1:]) / 1000000))
