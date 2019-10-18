@REM Assemble Vbootkit 2
nasm -f bin -o boot\vbootkit  vbootkit2.asm

@REM make an ISO with Vbootkit 2 embedded as boot sector
mkisofs -R -b grldr -no-emul-boot  -boot-load-size 4 -boot-info-table -o vbootkit2.iso boot

