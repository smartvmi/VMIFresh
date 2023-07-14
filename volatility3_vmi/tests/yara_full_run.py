from volatility3.plugins.linux import vmayarascan
from volatility3 import framework
from volatility3.framework import interfaces
from typing import Type
from os import listdir
from os.path import isfile, join
import sys
import gc
import os
import time
import statistics

clearcache = False
yara_path = "/root/build/td/volatility3/yara"

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

yara_files = [f for f in listdir(yara_path) if isfile(join(yara_path, f))]

results = []
for i in range(11):
    gc.disable()
    ms = 0
    for file in yara_files:
        ms = ms + silent_plugin_run(self, vmayarascan.VmaYaraScan, kernel = self.config["kernel"], yara_file = "file://" + yara_path + "/" + file)
    gc.enable()
    time.sleep(0.01)
    results.append(ms)
    print(f"[{i:3d}] {ms:.3f} ms")

print("=> Average: %.3f ms" % (statistics.mean(results[1:])),
      "Median: %.3f ms" % (statistics.median(results[1:])),
      "Stddev: %.3f ms" % (statistics.stdev(results[1:])))
