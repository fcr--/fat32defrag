# fat32defrag
FAT32 defragmenter written in pure lua!

**Notice:** As the author, I do not trust this defragmenter myself, I wrote it since I couldn't find any fat32 compactor-defragmenter able to run from linux, and I needed it for my Playstation 2 USB hard drive.  I have backups of the games and saves I place into that hdd, and so should you.

* **THIS IS A BETA PROJECT, IT MAY OR MAY NOT WORK WITH YOUR FAT32 FILESYSTEM.**
* **OTHER FILESYSTEM FORMATS ARE NOT SUPPORTED. PERIOD.**

## Usage:

If you plan on interrupting the defragmentation in the middle, then `sudo luarocks install luaposix`, otherwise don't complain if your filesystem gets corrupted (don't complain even if you've even installed it).

1. Backup `image_or_device_name`.
2. Calculate `tar -c path_to_where_image_or_device_is_mounted | md5sum`
3. Now ensure that the device is unmounted!
4. To be safe `fsck.vfat -V image_or_device_name`.
5. Run `./fat32defrag.lua image_or_device_name` first to ensure the filesystem can be defragmented correctly,
6. and only then `./fat32defrag.lua image_or_device_name defragment` if you're 100% sure that you would't mind ending with corrupt contents on that device.
7. Make sure the device is consistent, run fsck.vfat again (make sure no errors are thrown) and calculate the md5sum once more time.

## Creating a very fragmented test image with less than 10% free space:

The creation part (even though it's already included in the repo)
```
dd if=/dev/zero of=image.orig bs=$((1024*1024)) count=50
mkfs.vfat -F 32 image.orig
mkdir -p image.mountdir
sudo mount image.orig image.mountdir/ -o loop
cd image.mountdir
sudo luajit -e 'for i=1,1700000,100 do for n in("abc"):gmatch"."do fd=assert(io.open(n,"a"))for j=i,i+99 do fd:write(n," ",i,"\n")end fd:close()end end'
cd ..
sudo umount image.mountdir
rmdir image.mountdir
# then we can create a copy to avoid having to recreate it many times:
cp image.orig image
```

Defragmenting it:
```
./fat32defrag.lua image defragment
```
