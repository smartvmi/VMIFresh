# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import functools
import logging
import math
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

from volatility3 import classproperty
from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

libvmi = None
try:
    import libvmi
    from libvmi import LibvmiError
except ImportError:
    pass

class IntelVMI(linear.LinearlyMappedLayer):
    """Translation Layer for the Intel VMI memory mapping."""

    _direct_metadata = collections.ChainMap({'architecture': 'Intel64'}, {'mapped': True},
                                            interfaces.layers.TranslationLayerInterface._direct_metadata)

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)
        self._base_layer = self.config["memory_layer"]
        self._swap_layers = []  # type: List[str]
        self._page_map_offset = self.config["page_map_offset"]

    @classproperty
    def page_size(cls) -> int:
        """Page size for the intel memory layers.

        All Intel layers work on 4096 byte pages
        """
        return 1 << 12

    @classproperty
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    def maximum_address(cls) -> int:
        return (1 << 48) - 1

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all([
                self._context.layers[layer].is_valid(mapped_offset)
                for _, _, mapped_offset, _, layer in self.mapping(offset, length)
            ])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        # we are stacked on top of the VMILayer, so grab the instance here!
        vmi = self._context.layers[self._base_layer].vmi

        if length == 0:
            try:
                mapped_offset, layer_name = vmi.pagetable_lookup(self._page_map_offset, offset), self._base_layer
                if not self._context.layers[layer_name].is_valid(mapped_offset):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = mapped_offset)
            except Libexceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return
            except LibvmiError:
                if not ignore_errors:
                    raise exceptions.InvalidAddressException(layer_name = self._base_layer, invalid_address = offset)
                return
            yield offset, length, mapped_offset, length, layer_name
            return
        while length > 0:
            try:
                chunk_offset, layer_name = vmi.pagetable_lookup(self._page_map_offset, offset), self._base_layer
                chunk_size = min((1 << 12) - (chunk_offset % (1 << 12)), length)
                if not self._context.layers[layer_name].is_valid(chunk_offset, chunk_size):
                    raise exceptions.InvalidAddressException(layer_name = layer_name, invalid_address = chunk_offset)
            except (LibvmiError, exceptions.InvalidAddressException) as excp:
                if not ignore_errors:
                    raise exceptions.InvalidAddressException(layer_name = self._base_layer, invalid_address = offset)
                mask = (1 << 12) - 1
                length_diff = (mask + 1 - (offset & mask))
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layer names that this layer is dependent
        upon."""
        return [self._base_layer] + self._swap_layers

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'memory_layer', optional = False),
            requirements.LayerListRequirement(name = 'swap_layers', optional = True),
            requirements.IntRequirement(name = 'page_map_offset', optional = False),
            requirements.IntRequirement(name = 'kernel_virtual_offset', optional = True),
            requirements.StringRequirement(name = 'kernel_banner', optional = True)
        ]

