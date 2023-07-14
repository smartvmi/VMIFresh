from volatility3.plugins.linux import vmayarascan
from volatility3 import framework
from volatility3.framework import interfaces
from typing import Type
import sys
import gc
import os
import time
import statistics

clearcache = False

self.config["pid"] = int(input("Enter PID: "))

def silent_plugin_run(self, plugin: Type[interfaces.plugins.PluginInterface], **kwargs):
    if clearcache:
        ml = context.layers["memory_layer"]
        ml.__init__(ml.context, ml.config_path, ml.name)
        vl = context.layers["layer_name"]
        vl.read.cache_clear()
        framework.clear_cache()
        os.system("echo 3 > /proc/sys/vm/drop_caches")
    tg = generate_treegrid(plugin, **kwargs)
    if tg is None:
        print("FAILURE")
    def visitor(node: interfaces.renderers.TreeNode, accumulator):
        return accumulator
    start = time.perf_counter_ns()
    tg.populate(visitor, sys.stdout)
    end = time.perf_counter_ns()
    return (end - start) / 1000000

results = []
for i in range(101):
    gc.disable()
    ms = silent_plugin_run(self, vmayarascan.VmaYaraScan, kernel = self.config["kernel"], yara_file = "file:///root/build/td/volatility3/rule")
    gc.enable()
    time.sleep(0.01)
    results.append(ms)
    print(f"[{i:3d}] {ms:.3f} ms")

print("=> Average: %.3f ms" % (statistics.mean(results[1:])),
      "Median: %.3f ms" % (statistics.median(results[1:])),
      "Stddev: %.3f ms" % (statistics.stdev(results[1:])))
