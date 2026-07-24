#!/usr/bin/env python3
"""Generate the reviewed, source-attributed C64 symbol profile."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict


class Symbol(TypedDict, total=False):
    address: str
    name: str
    namespace: str
    kind: str
    primary: bool
    source_note: str


class Equate(TypedDict, total=False):
    name: str
    value: int
    description: str
    applications: list[dict[str, object]]


GUIDE_URL = (
    "https://www.commodore.ca/manuals/c64_programmers_reference/"
    "c64-programmers_reference.htm"
)
SID_URL = "https://www.cpcwiki.eu/imgs/9/9d/Mos_6581_sid.pdf"
CIA_URL = (
    "http://www.6502.org/documents/datasheets/mos/"
    "mos_6526_cia.pdf"
)
SERVICE_URL = (
    "https://www.commodore.ca/manuals/funet/cbm/schematics/"
    "computers/c64/manual-html/Page_07.html"
)

CPU_SOURCE = (
    "Commodore 64 Programmer's Reference Guide, Chapter 5, 6510 "
    f"processor port and memory map; {GUIDE_URL}"
)
VIC_SOURCE = (
    "Commodore 64 Programmer's Reference Guide, Chapter 3, VIC-II "
    f"register descriptions; {GUIDE_URL}"
)
SID_SOURCE = (
    "Commodore Semiconductor Group MOS 6581 SID data sheet, Table 1 "
    f"and register descriptions, pp. 2-6; {SID_URL}"
)
CIA_SOURCE = (
    "Commodore Semiconductor Group MOS 6526 CIA data sheet, register "
    f"map and descriptions; {CIA_URL}"
)
KERNAL_SOURCE = (
    "Commodore 64 Programmer's Reference Guide, Chapter 5, KERNAL "
    f"jump table and memory map, printed pp. 268-293; {GUIDE_URL}"
)
WORKSPACE_SOURCE = (
    "Commodore 64 Programmer's Reference Guide, Chapter 5, C64 "
    f"memory map and KERNAL workspace; {GUIDE_URL}"
)
BLOCK_SOURCE = (
    "Commodore 64 Service Manual, I/O and ROM address decoding; "
    f"{SERVICE_URL}"
)


def symbol(
    address: int,
    name: str,
    namespace: str,
    source: str,
    *,
    kind: str = "label",
) -> Symbol:
    return {
        "address": f"{address:04x}",
        "name": name,
        "namespace": namespace,
        "kind": kind,
        "primary": False,
        "source_note": source,
    }


def equate(
    name: str,
    value: int,
    description: str,
    source: str,
) -> Equate:
    return {
        "name": name,
        "value": value,
        "description": f"{description}. Source: {source}",
        "applications": [],
    }


def register_symbols(
    start: int,
    names: list[str],
    namespace: str,
    source: str,
) -> list[Symbol]:
    return [
        symbol(start + offset, name, namespace, source)
        for offset, name in enumerate(names)
    ]


def sprite_mask_equates(
    register: str,
    description: str,
) -> list[Equate]:
    return [
        equate(
            f"C64_VIC_{register}_SPRITE{sprite}",
            1 << sprite,
            f"{description} for sprite {sprite}",
            VIC_SOURCE,
        )
        for sprite in range(8)
    ]


def profile() -> dict[str, object]:
    symbols: list[Symbol] = [
        symbol(0x0000, "PROCESSOR_PORT_DIRECTION", "C64::CPU", CPU_SOURCE),
        symbol(0x0001, "PROCESSOR_PORT", "C64::CPU", CPU_SOURCE),
    ]

    vic_names = [
        *(name for sprite in range(8) for name in (
            f"SPRITE{sprite}_X",
            f"SPRITE{sprite}_Y",
        )),
        "SPRITE_X_MSB",
        "CONTROL_1",
        "RASTER",
        "LIGHT_PEN_X",
        "LIGHT_PEN_Y",
        "SPRITE_ENABLE",
        "CONTROL_2",
        "SPRITE_Y_EXPAND",
        "MEMORY_POINTERS",
        "INTERRUPT_STATUS",
        "INTERRUPT_ENABLE",
        "SPRITE_PRIORITY",
        "SPRITE_MULTICOLOR",
        "SPRITE_X_EXPAND",
        "SPRITE_SPRITE_COLLISION",
        "SPRITE_BACKGROUND_COLLISION",
        "BORDER_COLOR",
        "BACKGROUND_COLOR_0",
        "BACKGROUND_COLOR_1",
        "BACKGROUND_COLOR_2",
        "BACKGROUND_COLOR_3",
        "SPRITE_MULTICOLOR_0",
        "SPRITE_MULTICOLOR_1",
        *(f"SPRITE{sprite}_COLOR" for sprite in range(8)),
    ]
    symbols.extend(
        register_symbols(0xD000, vic_names, "C64::VIC", VIC_SOURCE)
    )
    symbols.append(
        symbol(0xD800, "COLOR_RAM", "C64::VIC", VIC_SOURCE)
    )

    sid_names = [
        "VOICE1_FREQ_LO",
        "VOICE1_FREQ_HI",
        "VOICE1_PULSE_LO",
        "VOICE1_PULSE_HI",
        "VOICE1_CONTROL",
        "VOICE1_ATTACK_DECAY",
        "VOICE1_SUSTAIN_RELEASE",
        "VOICE2_FREQ_LO",
        "VOICE2_FREQ_HI",
        "VOICE2_PULSE_LO",
        "VOICE2_PULSE_HI",
        "VOICE2_CONTROL",
        "VOICE2_ATTACK_DECAY",
        "VOICE2_SUSTAIN_RELEASE",
        "VOICE3_FREQ_LO",
        "VOICE3_FREQ_HI",
        "VOICE3_PULSE_LO",
        "VOICE3_PULSE_HI",
        "VOICE3_CONTROL",
        "VOICE3_ATTACK_DECAY",
        "VOICE3_SUSTAIN_RELEASE",
        "FILTER_CUTOFF_LO",
        "FILTER_CUTOFF_HI",
        "FILTER_RESONANCE_ROUTING",
        "FILTER_MODE_VOLUME",
        "PADDLE_X",
        "PADDLE_Y",
        "OSCILLATOR3_RANDOM",
        "ENVELOPE3",
    ]
    symbols.extend(
        register_symbols(0xD400, sid_names, "C64::SID", SID_SOURCE)
    )

    cia_names = [
        "DATA_PORT_A",
        "DATA_PORT_B",
        "DATA_DIRECTION_A",
        "DATA_DIRECTION_B",
        "TIMER_A_LO",
        "TIMER_A_HI",
        "TIMER_B_LO",
        "TIMER_B_HI",
        "TOD_TENTHS",
        "TOD_SECONDS",
        "TOD_MINUTES",
        "TOD_HOURS",
        "SERIAL_DATA",
        "INTERRUPT_CONTROL",
        "CONTROL_A",
        "CONTROL_B",
    ]
    symbols.extend(
        register_symbols(0xDC00, cia_names, "C64::CIA1", CIA_SOURCE)
    )
    symbols.extend(
        register_symbols(0xDD00, cia_names, "C64::CIA2", CIA_SOURCE)
    )

    kernal_entries = [
        (0xFF81, "CINT"),
        (0xFF84, "IOINIT"),
        (0xFF87, "RAMTAS"),
        (0xFF8A, "RESTOR"),
        (0xFF8D, "VECTOR"),
        (0xFF90, "SETMSG"),
        (0xFF93, "SECOND"),
        (0xFF96, "TKSA"),
        (0xFF99, "MEMTOP"),
        (0xFF9C, "MEMBOT"),
        (0xFF9F, "SCNKEY"),
        (0xFFA2, "SETTMO"),
        (0xFFA5, "ACPTR"),
        (0xFFA8, "CIOUT"),
        (0xFFAB, "UNTLK"),
        (0xFFAE, "UNLSN"),
        (0xFFB1, "LISTEN"),
        (0xFFB4, "TALK"),
        (0xFFB7, "READST"),
        (0xFFBA, "SETLFS"),
        (0xFFBD, "SETNAM"),
        (0xFFC0, "OPEN"),
        (0xFFC3, "CLOSE"),
        (0xFFC6, "CHKIN"),
        (0xFFC9, "CHKOUT"),
        (0xFFCC, "CLRCHN"),
        (0xFFCF, "CHRIN"),
        (0xFFD2, "CHROUT"),
        (0xFFD5, "LOAD"),
        (0xFFD8, "SAVE"),
        (0xFFDB, "SETTIM"),
        (0xFFDE, "RDTIM"),
        (0xFFE1, "STOP"),
        (0xFFE4, "GETIN"),
        (0xFFE7, "CLALL"),
        (0xFFEA, "UDTIM"),
        (0xFFED, "SCREEN"),
        (0xFFF0, "PLOT"),
        (0xFFF3, "IOBASE"),
    ]
    symbols.extend(
        symbol(
            address,
            name,
            "C64::KERNAL",
            KERNAL_SOURCE,
            kind="entry_point",
        )
        for address, name in kernal_entries
    )
    symbols.extend(
        symbol(address, name, "C64::KERNAL", KERNAL_SOURCE)
        for address, name in [
            (0xFFFA, "NMI_VECTOR"),
            (0xFFFC, "RESET_VECTOR"),
            (0xFFFE, "IRQ_VECTOR"),
        ]
    )

    workspace = [
        (0x0090, "IO_STATUS"),
        (0x0091, "STOP_KEY_FLAG"),
        (0x0099, "DEFAULT_INPUT_DEVICE"),
        (0x009A, "DEFAULT_OUTPUT_DEVICE"),
        (0x00C6, "KEYBOARD_BUFFER_LENGTH"),
        (0x00D3, "CURSOR_COLUMN"),
        (0x00D6, "CURSOR_ROW"),
        (0x0286, "TEXT_COLOR"),
        (0x0288, "SCREEN_MEMORY_PAGE"),
        (0x0314, "IRQ_RAM_VECTOR"),
        (0x0316, "BRK_RAM_VECTOR"),
        (0x0318, "NMI_RAM_VECTOR"),
    ]
    symbols.extend(
        symbol(address, name, "C64::WORKSPACE", WORKSPACE_SOURCE)
        for address, name in workspace
    )

    equates: list[Equate] = [
        equate(
            "C64_VIC_CONTROL1_RASTER_MSB",
            0x80,
            "Raster compare bit 8",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL1_EXTENDED_COLOR_MODE",
            0x40,
            "Extended color text mode enable",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL1_BITMAP_MODE",
            0x20,
            "Bitmap mode enable",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL1_DISPLAY_ENABLE",
            0x10,
            "Display enable",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL1_ROW_SELECT",
            0x08,
            "25-row display select",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL1_VERTICAL_SCROLL_MASK",
            0x07,
            "Vertical fine-scroll field mask",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL2_MULTICOLOR_MODE",
            0x10,
            "Multicolor text or bitmap mode enable",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL2_COLUMN_SELECT",
            0x08,
            "40-column display select",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_CONTROL2_HORIZONTAL_SCROLL_MASK",
            0x07,
            "Horizontal fine-scroll field mask",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_MEMORY_SCREEN_MASK",
            0xF0,
            "Screen-memory pointer field mask",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_MEMORY_CHARACTER_MASK",
            0x0E,
            "Character or bitmap memory pointer field mask",
            VIC_SOURCE,
        ),
        equate(
            "C64_VIC_IRQ_STATUS_ANY",
            0x80,
            "At least one enabled VIC-II interrupt is pending",
            VIC_SOURCE,
        ),
    ]
    for suffix, value, description in [
        ("LIGHT_PEN", 0x08, "Light-pen interrupt"),
        ("SPRITE_SPRITE", 0x04, "Sprite-sprite collision interrupt"),
        ("SPRITE_BACKGROUND", 0x02, "Sprite-background collision interrupt"),
        ("RASTER", 0x01, "Raster compare interrupt"),
    ]:
        equates.append(
            equate(
                f"C64_VIC_IRQ_STATUS_{suffix}",
                value,
                description + " status",
                VIC_SOURCE,
            )
        )
        equates.append(
            equate(
                f"C64_VIC_IRQ_ENABLE_{suffix}",
                value,
                description + " enable",
                VIC_SOURCE,
            )
        )
    for register, description in [
        ("X_MSB", "Horizontal-position high bit"),
        ("ENABLE", "Enable bit"),
        ("Y_EXPAND", "Vertical expansion bit"),
        ("PRIORITY", "Behind-background priority bit"),
        ("MULTICOLOR", "Multicolor enable bit"),
        ("X_EXPAND", "Horizontal expansion bit"),
    ]:
        equates.extend(sprite_mask_equates(register, description))

    for name, value, description in [
        ("GATE", 0x01, "Envelope gate"),
        ("SYNC", 0x02, "Oscillator synchronization"),
        ("RING_MOD", 0x04, "Ring modulation"),
        ("TEST", 0x08, "Oscillator test"),
        ("TRIANGLE", 0x10, "Triangle waveform"),
        ("SAWTOOTH", 0x20, "Sawtooth waveform"),
        ("PULSE", 0x40, "Pulse waveform"),
        ("NOISE", 0x80, "Noise waveform"),
    ]:
        equates.append(
            equate(f"C64_SID_CONTROL_{name}", value, description, SID_SOURCE)
        )
    for name, value, description in [
        ("VOICE1", 0x01, "Route voice 1 through filter"),
        ("VOICE2", 0x02, "Route voice 2 through filter"),
        ("VOICE3", 0x04, "Route voice 3 through filter"),
        ("EXTERNAL", 0x08, "Route external input through filter"),
        ("RESONANCE_MASK", 0xF0, "Filter resonance field mask"),
    ]:
        equates.append(
            equate(f"C64_SID_FILTER_{name}", value, description, SID_SOURCE)
        )
    for name, value, description in [
        ("VOLUME_MASK", 0x0F, "Master volume field mask"),
        ("LOW_PASS", 0x10, "Low-pass filter enable"),
        ("BAND_PASS", 0x20, "Band-pass filter enable"),
        ("HIGH_PASS", 0x40, "High-pass filter enable"),
        ("VOICE3_OFF", 0x80, "Disconnect unfiltered voice 3"),
    ]:
        equates.append(
            equate(f"C64_SID_MODE_{name}", value, description, SID_SOURCE)
        )

    for name, value, description in [
        ("TIMER_A", 0x01, "Timer A interrupt"),
        ("TIMER_B", 0x02, "Timer B interrupt"),
        ("ALARM", 0x04, "Time-of-day alarm interrupt"),
        ("SERIAL", 0x08, "Serial-port interrupt"),
        ("FLAG", 0x10, "FLAG pin interrupt"),
        ("SET_CLEAR", 0x80, "Set or clear selected interrupt masks"),
    ]:
        equates.append(
            equate(f"C64_CIA_ICR_{name}", value, description, CIA_SOURCE)
        )
    for register, fields in {
        "CRA": [
            ("START", 0x01, "Start timer A"),
            ("PBON", 0x02, "Timer A output on port B"),
            ("OUTMODE", 0x04, "Timer A output mode"),
            ("RUNMODE", 0x08, "Timer A one-shot mode"),
            ("LOAD", 0x10, "Force timer A latch load"),
            ("INMODE", 0x20, "Timer A CNT input mode"),
            ("SPMODE", 0x40, "Serial-port output mode"),
            ("TODIN", 0x80, "50 Hz time-of-day input select"),
        ],
        "CRB": [
            ("START", 0x01, "Start timer B"),
            ("PBON", 0x02, "Timer B output on port B"),
            ("OUTMODE", 0x04, "Timer B output mode"),
            ("RUNMODE", 0x08, "Timer B one-shot mode"),
            ("LOAD", 0x10, "Force timer B latch load"),
            ("INMODE0", 0x20, "Timer B input-mode field bit 0"),
            ("INMODE1", 0x40, "Timer B input-mode field bit 1"),
            ("ALARM", 0x80, "Time-of-day alarm write select"),
        ],
    }.items():
        for name, value, description in fields:
            equates.append(
                equate(
                    f"C64_CIA_{register}_{name}",
                    value,
                    description,
                    CIA_SOURCE,
                )
            )

    memory_blocks = [
        {
            "name": "RAM",
            "start": "0000",
            "length": 0x10000,
            "fill": 0,
            "overlay": False,
            "read": True,
            "write": True,
            "execute": True,
            "comment": f"C64 64 KiB RAM template. Source: {BLOCK_SOURCE}",
        },
        {
            "name": "BASIC_ROM",
            "start": "a000",
            "length": 0x2000,
            "fill": 0,
            "overlay": True,
            "read": True,
            "write": False,
            "execute": True,
            "comment": f"C64 BASIC ROM overlay template. Source: {BLOCK_SOURCE}",
        },
        {
            "name": "KERNAL_ROM",
            "start": "e000",
            "length": 0x2000,
            "fill": 0,
            "overlay": True,
            "read": True,
            "write": False,
            "execute": True,
            "comment": f"C64 KERNAL ROM overlay template. Source: {BLOCK_SOURCE}",
        },
        {
            "name": "IO",
            "start": "d000",
            "length": 0x1000,
            "fill": 0,
            "overlay": True,
            "read": True,
            "write": True,
            "execute": False,
            "comment": f"C64 I/O overlay template. Source: {BLOCK_SOURCE}",
        },
        {
            "name": "COLOR_RAM",
            "start": "d800",
            "length": 0x0400,
            "fill": 0,
            "overlay": True,
            "read": True,
            "write": True,
            "execute": False,
            "comment": f"C64 color RAM overlay template. Source: {BLOCK_SOURCE}",
        },
    ]

    return {
        "schema_version": 1,
        "id": "c64",
        "version": "1.0.0",
        "description": (
            "Commodore 64 platform symbols, value-only control equates, "
            "and opt-in memory templates. Sources: Commodore 64 "
            f"Programmer's Reference Guide ({GUIDE_URL}); MOS/Commodore "
            f"6581 SID data sheet ({SID_URL}); MOS/Commodore 6526 CIA "
            f"data sheet ({CIA_URL}); Commodore 64 Service Manual "
            f"({SERVICE_URL})."
        ),
        "symbols": symbols,
        "equates": equates,
        "comments": [],
        "memory_blocks": memory_blocks,
    }


def main() -> None:
    target = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ghidra_mcp_c64"
        / "profiles"
        / "c64.json"
    )
    target.write_text(
        json.dumps(
            profile(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
