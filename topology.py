from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def run():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    net.start()
    print("\n=== NETWORK READY ===")
    print("Commands to test:")
    print("  h1 ping h2  # ICMP - should work")
    print("  h1 ping h3  # ICMP - should be BLOCKED")
    print("  h2 iperf -s & ; h1 iperf -c h2  # TCP")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
