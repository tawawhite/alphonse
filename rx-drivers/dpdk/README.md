# DPDK rx-driver

## 1. DPDK deployment requirements

### 1.1 [Configure huge pages](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/configuring-huge-pages_monitoring-and-managing-system-status-and-performance)

1. Create a HugeTLB pool for 1 GB pages by appending the following line to the kernel command-line options in the `/etc/default/grub` file as root:

    ```
    default_hugepagesz=1G hugepagesz=1G
    ```

2. Regenerate the GRUB2 configuration using the edited default file:

    ```bash
    # RedHat 8 system
    grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

    # Rocky Linux 8 system
    grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg
    ```

3. Create a new file called hugetlb-gigantic-pages.service in the /usr/lib/systemd/system/ directory and add the following content:

    ```
    [Unit]
    Description=HugeTLB Gigantic Pages Reservation
    DefaultDependencies=no
    Before=dev-hugepages.mount
    ConditionPathExists=/sys/devices/system/node
    ConditionKernelCommandLine=hugepagesz=1G
    
    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/lib/systemd/hugetlb-reserve-pages.sh
    
    [Install]
    WantedBy=sysinit.target
    ```

4. Create a new file called hugetlb-reserve-pages.sh in the /usr/lib/systemd/ directory and add the following content:

    While adding the following content, replace number_of_pages with the number of 1GB pages you want to reserve, and node with the name of the node on which to reserve these pages.

    ```bash
    #!/bin/sh

    nodes_path=/sys/devices/system/node/
    if [ ! -d $nodes_path ]; then
        echo "ERROR: $nodes_path does not exist"
        exit 1
    fi

    reserve_pages()
    {
        echo $1 > $nodes_path/$2/hugepages/hugepages-1048576kB/nr_hugepages
    }

    # For example reserve 8GB huge pages for a 16GB single node system
    reserve_pages 8 node0

    mkdir -p /dev/hugepages1G
    mount -t hugetlbfs -o pagesize=1G none /dev/hugepages1G
    ```

5. Create an executable script:

    ```bash
    chmod +x /usr/lib/systemd/hugetlb-reserve-pages.sh
    ```

6. Enable early boot reservation:

    ```bash
    systemctl enable hugetlb-gigantic-pages
    ```

7. Reboot system

8. Check huge pages:

    ```shell
    > cat /proc/meminfo | grep Huge
    AnonHugePages:    122880 kB
    ShmemHugePages:        0 kB
    FileHugePages:         0 kB
    HugePages_Total:       8
    HugePages_Free:        8
    HugePages_Rsvd:        0
    HugePages_Surp:        0
    Hugepagesize:    1048576 kB
    Hugetlb:         8388608 kB
    ```