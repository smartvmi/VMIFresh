from volatility3.plugins.linux import bash, check_afinfo, check_creds, check_idt, check_modules, check_syscall, elfs, envars, envvars
from volatility3.plugins.linux import keyboard_notifiers, lsmod, lsof, malfind, mountinfo, proc, psaux, pslist, psscan, pstree, sockstat
from volatility3 import framework
from volatility3.framework import interfaces
from typing import Type
import sys
import gc
import os
import time
import statistics

clearcache = False

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

def run_plugins(self):
    ms = 0
    # commented out plugins have version specific code that did not work on our kernel or are duplicates
    ms = ms + silent_plugin_run(self, bash.Bash, kernel = self.config["kernel"])
    # ms = ms + silent_plugin_run(self, check_afinfo.Check_afinfo, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, check_creds.Check_creds, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, check_idt.Check_idt, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, check_syscall.Check_syscall, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, check_modules.Check_modules, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, elfs.Elfs, kernel = self.config["kernel"])
    # ms = ms + silent_plugin_run(self, envars.Envars, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, envvars.Envvars, kernel = self.config["kernel"])
    # ms = ms + silent_plugin_run(self, iomem.IOMem, kernel = self.config["kernel"])
    # ms = ms + silent_plugin_run(self, kmsg.Kmsg, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, lsmod.Lsmod, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, lsof.Lsof, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, keyboard_notifiers.Keyboard_notifiers, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, malfind.Malfind, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, mountinfo.MountInfo, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, proc.Maps, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, psaux.PsAux, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, pslist.PsList, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, psscan.PsScan, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, pstree.PsTree, kernel = self.config["kernel"])
    ms = ms + silent_plugin_run(self, sockstat.Sockstat, kernel = self.config["kernel"])
    # ms = ms + silent_plugin_run(self, tty_check.tty_check, kernel = self.config["kernel"])
    return ms

results = []
for i in range(101):
    gc.disable()
    ms = run_plugins(self)
    gc.enable()
    time.sleep(0.01)
    results.append(ms)
    print(f"[{i:3d}] {ms:.3f} ms")

print("=> Average: %.3f ms" % (statistics.mean(results[1:])),
      "Median: %.3f ms" % (statistics.median(results[1:])),
      "Stddev: %.3f ms" % (statistics.stdev(results[1:])))

