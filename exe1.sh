mount fat32.disk /mnt/disk;

rm /mnt/disk/HELLO.TXT;
y;
sync;

umount /mnt/disk;
./nyufile fat32.disk -l;