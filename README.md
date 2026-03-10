# IdaSwitch

IdaSwitch is a decompilation of Peter Garba's excellent [SwitchIDAProLoader](https://github.com/pgarba/SwitchIDAProLoader).

This decompilation is based on v0.25 of the loader and is built with IDA 9.0 in mind. Testing has been done for Windows and macOS, but Linux is currently untested.

# Building

## Requirements
- **CMake**, version 3.23 or above.
- **IDA_SDK** configured in the environment, which must be a path (*no trailing slashes!*) to the IDA SDK.

First, clone the repository, following up with `git submodule update --init --recursive` once complete to initialize the submodules.

From there, do `cmake -B build IdaSwitch` to create the build folder, adding arguments as necessary. Finally, do `cmake --build build` to generate the binaries.

# Special Thanks

- [Peter Garba](https://github.com/pgarba) for creating the original loader; reverse engineering of Switch games with IDA wouldn't be as accessible without their awesome work.
- The [Atmosphère](https://github.com/Atmosphere-NX) developers for their amazing work regarding the Switch. The Kernel Initial Process (KIP) reader was heavily referenced for this decompilation, including its BLZ decompression function.
- [ReSwitched Team](https://github.com/reswitched) for their excellent [loaders](https://github.com/reswitched/loaders), which was heavily referenced for symbol recovery.
- [SwitchBrew](https://switchbrew.org/wiki/Main_Page) for their incredibly in-depth resources regarding the Switch.
