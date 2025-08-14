mac1=$1
mac2=$2
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci
interfaces=$(ip -o link  | awk '{print $2,$(NF-4)}' | egrep "$mac1|$mac2" | awk -F ':' '{print $1}')
for interface in $interfaces;do
   ip link set down $interface
   pci_addr=$(ethtool -i $interface | awk '{if ($1 == "bus-info:") print $2}')
   driverctl set-override $pci_addr vfio-pci
done
tmux new-session -d -s "testpmd" /bin/dpdk-testpmd -l 3,4,5 -n 4 --socket-mem 1024 -- -i --nb-cores=2 --auto-start --forward-mode=io

