target_sources(IdaSwitch
  PRIVATE
    "lz4/lib/lz4.c"
    "lz4/lib/lz4file.c"
    "lz4/lib/lz4frame.c"
    "lz4/lib/lz4hc.c"
    "lz4/lib/xxhash.c"
)

target_include_directories(IdaSwitch
  PRIVATE lz4/lib/
)