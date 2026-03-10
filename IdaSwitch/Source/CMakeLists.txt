target_sources(IdaSwitch
  PRIVATE
    "BlzCompression.cpp"
    "ConfigureDatabase.cpp"
    "LoaderMain.cpp"
    "LoadKip.cpp"
    "LoadNro.cpp"
    "LoadNso.cpp"
    "SymbolRecovery.cpp"

  PRIVATE FILE_SET HEADERS
    FILES
      "AddressingConstants.h"
      "BasicTypes.h"
      "BlzCompression.h"
      "ConfigureDatabase.h"
      "Elf.h"
      "IdaSwitch.h"
      "LoadImplementations.h"
      "Module.h"
      "SegmentConstants.h"
      "StringizeHelpers.h"
      "SymbolRecovery.h"
)
