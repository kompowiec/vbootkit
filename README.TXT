Vbootkit 2.0 ( source and binary download)
==============================================

Warning :- We are not responsible for anything.Use at your own risk

developers:
Vipin Kumar   :  vipin at nvlabs.in
Nitin Kumar   :  nitin at nvlabs.in

visit www.nvlabs.in for more information or updates.

If you develop anything using this code, please remember to give necessary credit to the authors.

mails:-


This zip contains Vbootkit 2.0 ( both binary and source code).
The source code is available under GPL license.

Here are the basic usage instrcutions and the layout.

build  -> Contains Vbootkit 2.0 source code, nasm and mkisofs to build a bootable CD image
pingv  -> Contains customised ping source code to send and receive commands to system affected with Vbootkit 2.0
sample -> Contains a screenshot and a small video showing vbootkit 2.0 in action.

For more information, such as How Vbootkit works, download the presentation from nvlabs.in

NOTE: Vbootkit 2.0 currently works on Windows 7 Beta, build 7000 x64 edition to be exact and might/might-not work with other versions or builds.Minor changes might be required to support the other builds/versions.


Compiling Vbootkit 2.0
======================

switch to build directory and run build.bat
This will give you an ISO image containing Vbootkit 2, which can be used to test out functionality

*A pre-build ISO already exists, so as users can directly test it out


To compile pingv client, you can use Visual Studio ( express edition works fine) and build the exe yourself.Just in case, prebuilt EXE's are also there in the directory.

Testing Vbootkit 2.0
======================

Just boot the Windows 7 system, using the Vbootkit 2 CD and uncross your fingers ( so as you can type commands !!!)

Now, execute pingv.exe IP address command-code

The command codes are  
		Command Code      Action 
		0                 Get Signature immediate 
		1                 Get Signature Delayed
		2                 Get Keylog data 
		3                 Escalate CMD.EXE privileges
		4                 Reset Passwords/Set Passwords( toggles between states) ( This effect can be persistant )
		


Vbootkit does not try to stick to your system in any case.


Feel free to mail/comment/query.



 
