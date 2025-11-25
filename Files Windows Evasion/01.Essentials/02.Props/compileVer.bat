@ECHO OFF

rc ver.rc
cvtres /MACHINE:x64 /OUT:ver.o ver.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 ver.o

del *.obj *.o *.res
