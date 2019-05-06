On c8220 node:
    $ ssh ral@clnode001.clemson.cloudlab.us
    $ echo -e "d\n4\nn\np\n\n+16G\nw\n" | sudo fdisk /dev/sda
    $ sudo systemctl reboot
    $ sudo mkfs -F -t ext3 /dev/sda4
    $ sudo mkdir -p /mnt/linux-4.15_milliscope-0.01
    $ sudo mount /dev/sda4 /mnt/linux-4.15_milliscope-0.01
    $ sudo chown ral /mnt/linux-4.15_milliscope-0.01
    $ sudo su
    $ echo "/dev/sda4 /mnt/linux-4.15_milliscope-0.01 ext3 defaults 0 0" >> /etc/fstab
    $ exit
    $ exit
    $ scp linux-4.15_milliscope-0.01.tar.gz ral@clnode001.clemson.cloudlab.us:/mnt/linux-4.15_milliscope-0.01
    $ ssh ral@clnode001.clemson.cloudlab.us
    $ cd /mnt/linux-4.15_milliscope-0.01
    $ wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.15.tar.gz
    $ tar -xvzf linux-4.15.tar.gz
    $ tar -xvzf linux-4.15_milliscope-0.01.tar.gz
    $ cd linux-4.15
    $ cp -v /boot/config-$(uname -r) .config
    $ make -j $(nproc)
    $ sudo make modules_install
    $ sudo make install
    $ vi /boot/grub/grub.cfg
    $ sudo vi /etc/default/grub
    $ sudo update-grub
    $ sudo systemctl reboot

On d430 node:
    $ ssh ral@node1.[experiment-name].Infosphere.emulab.net
    $ echo -e "d\n4\nn\np\n\n+64G\nw\n" | sudo fdisk /dev/sda
    $ sudo systemctl reboot
    $ sudo mkfs -F -t ext3 /dev/sda4
    $ sudo mkdir -p /mnt/linux-4.15_milliscope-0.01
    $ sudo mount /dev/sda4 /mnt/linux-4.15_milliscope-0.01
    $ sudo chown ral /mnt/linux-4.15_milliscope-0.01
    $ sudo su
    $ echo "/dev/sda4 /mnt/linux-4.15_milliscope-0.01 ext3 defaults 0 0" >> /etc/fstab
    $ exit
    $ exit
    $ scp linux-4.15_milliscope-0.01.tar.gz ral@node1.[experiment-name].Infosphere.emulab.net:/mnt/linux-4.15_milliscope-0.01
    $ ssh ral@node1.[experiment-name].Infosphere.emulab.net
    $ cd /mnt/linux-4.15_milliscope-0.01
    $ wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.15.tar.gz
    $ tar -xvzf linux-4.15.tar.gz
    $ tar -xvzf linux-4.15_milliscope-0.01.tar.gz
    $ cd linux-4.15
    $ cp -v /boot/config-$(uname -r) .config
    $ make -j $(nproc)
    $ sudo make modules_install
    $ sudo make install
    $ vi /boot/grub/grub.cfg
    $ sudo vi /etc/default/grub
    $ sudo update-grub
    $ sudo systemctl reboot
    $ cd /mnt/linux-4.15_milliscope-0.01/linux-4.15
    $ make clean

On d430 node (use separate build directory):
    $ ssh ral@node1.image2.Infosphere.emulab.net
    $ echo -e "d\n4\nn\np\n\n+32G\nw\n" | sudo fdisk /dev/sda
    $ sudo systemctl reboot
    $ ssh ral@node1.image2.Infosphere.emulab.net
    $ sudo su
    $ mkfs -F -t ext3 /dev/sda4
    $ mkdir -p /mnt/linux-4.15_milliScope-0.01
    $ mount /dev/sda4 /mnt/linux-4.15_milliScope-0.01
    $ chown ral /mnt/linux-4.15_milliScope-0.01
    $ echo "/dev/sda4 /mnt/linux-4.15_milliScope-0.01 ext3 defaults 0 0" >> /etc/fstab
    $ exit
    $ exit
    $ scp linux-4.15_milliScope-0.01.tar.gz ral@node1.image2.Infosphere.emulab.net:/mnt/linux-4.15_milliScope-0.01
    $ ssh ral@node1.image2.Infosphere.emulab.net
    $ cd /mnt/linux-4.15_milliScope-0.01
    $ wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.15.tar.gz
    $ tar -xvzf linux-4.15.tar.gz
    $ tar -xvzf linux-4.15_milliScope-0.01.tar.gz
    $ cd linux-4.15
    $ cp -v /boot/config-$(uname -r) .config
    $ make -j $(nproc)
    $ sudo su
    $ make modules_install
    $ make install
    $ make clean
    $ vi /boot/grub/grub.cfg
    $ vi /etc/default/grub
    $ update-grub
    $ systemctl reboot
    $ ssh ral@node1.image2.Infosphere.emulab.net
