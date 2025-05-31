#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/point-to-point-module.h"
#include "myapp.h"

NS_LOG_COMPONENT_DEFINE("Wormhole");

using namespace ns3;

void ReceivePacket(Ptr<const Packet> p, const Address &addr)
{
    std::cout << Simulator::Now().GetSeconds() << "\t" << p->GetSize() << "\n";
}

void create_nodes(NodeContainer &c, NodeContainer &nm, NodeContainer &m)
{
    NS_LOG_INFO("Create Nodes");

    c.Create(10);

    nm.Add(c.Get(0)); // SourceNode
    nm.Add(c.Get(3)); // SinkNode
    nm.Add(c.Get(4)); // NormalNode1
    nm.Add(c.Get(5)); // NormalNode2
    nm.Add(c.Get(6)); // NormalNode3
    nm.Add(c.Get(7)); // NormalNode4
    nm.Add(c.Get(8)); // NormalNode5
    nm.Add(c.Get(9)); // NormalNode6

    m.Add(c.Get(1));  // MaliciousNode1
    m.Add(c.Get(2));  // MaliciousNode2

    // Assign names to nodes
    Names::Add("SourceNode", c.Get(0));
    Names::Add("MaliciousNode1", c.Get(1));
    Names::Add("MaliciousNode2", c.Get(2));
    Names::Add("SinkNode", c.Get(3));
    Names::Add("NormalNode1", c.Get(4));
    Names::Add("NormalNode2", c.Get(5));
    Names::Add("NormalNode3", c.Get(6));
    Names::Add("NormalNode4", c.Get(7));
    Names::Add("NormalNode5", c.Get(8));
    Names::Add("NormalNode6", c.Get(9));
}

void wormhole(int param_count, char *param_list[])
{
    bool enableFlowMonitor = false;
    std::string phyMode("DsssRate1Mbps");

    CommandLine cmd;
    cmd.AddValue("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
    cmd.AddValue("phyMode", "Wifi Phy mode", phyMode);
    cmd.Parse(param_count, param_list);

    // Enable AODV logging for detailed debugging
    LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

    // Create Nodes
    NodeContainer c;
    NodeContainer malicious;
    NodeContainer not_malicious;

    create_nodes(c, not_malicious, malicious);

    // Setup Wi-Fi
    WifiHelper wifi;
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");
    wifiPhy.SetPcapDataLinkType(YansWifiPhyHelper::DLT_IEEE802_11);
    wifiPhy.Set("TxPowerStart", DoubleValue(15.0)); // Increased transmission power to ensure MaliciousNode2 to SinkNode connection
    wifiPhy.Set("TxPowerEnd", DoubleValue(15.0));

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::TwoRayGroundPropagationLossModel", 
                                   "SystemLoss", DoubleValue(1), 
                                   "HeightAboveZ", DoubleValue(1.5));

    wifiPhy.SetChannel(wifiChannel.Create());

    // Add a non-QoS upper MAC
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    // Set 802.11b standard
    wifi.SetStandard(WIFI_PHY_STANDARD_80211b);

    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue(phyMode),
                                "ControlMode", StringValue(phyMode));

    // Install Wi-Fi devices on non-malicious and malicious nodes
    NetDeviceContainer not_mal_devices = wifi.Install(wifiPhy, wifiMac, not_malicious);
    NetDeviceContainer mal_devices = wifi.Install(wifiPhy, wifiMac, malicious);

    // Setup Point-to-Point link for Wormhole tunnel between malicious nodes
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("1ms"));
    NetDeviceContainer tunnelDevices = p2p.Install(malicious);

    // Enable AODV
    AodvHelper aodv;
    AodvHelper malicious_aodv;

    // Set up internet stack for non-malicious nodes
    InternetStackHelper internet;
    internet.SetRoutingHelper(aodv);
    internet.Install(not_malicious);

    // Configure malicious nodes for Wormhole attack
    malicious_aodv.Set("EnableWrmAttack", BooleanValue(true));
    malicious_aodv.Set("EnableHello", BooleanValue(false)); // Disable Hello messages to strengthen wormhole path
    internet.SetRoutingHelper(malicious_aodv);
    internet.Install(malicious);

    // Set up IP addresses
    Ipv4AddressHelper ipv4;
    NS_LOG_INFO("Assign IP Addresses for Wi-Fi devices");
    ipv4.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer not_mal_ifcont = ipv4.Assign(not_mal_devices);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer mal_ifcont = ipv4.Assign(mal_devices);

    ipv4.SetBase("10.2.3.0", "255.255.255.0");
    Ipv4InterfaceContainer tunnelIfcont = ipv4.Assign(tunnelDevices);

    // Set Wormhole tunnel endpoints to malicious nodes' Wi-Fi addresses
    malicious_aodv.Set("FirstEndWifiWormTunnel", Ipv4AddressValue(mal_ifcont.GetAddress(0))); // MaliciousNode1
    malicious_aodv.Set("SecondEndWifiWormTunnel", Ipv4AddressValue(mal_ifcont.GetAddress(1))); // MaliciousNode2

    NS_LOG_INFO("Create Applications");

    // UDP connection from SourceNode to SinkNode
    uint16_t sinkPort = 6;
    Address sinkAddress(InetSocketAddress(not_mal_ifcont.GetAddress(1), sinkPort)); // SinkNode
    PacketSinkHelper packetSinkHelper("ns3::UdpSocketFactory", 
                                     InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
    ApplicationContainer sinkApps = packetSinkHelper.Install(c.Get(3)); // SinkNode
    sinkApps.Start(Seconds(0.));
    sinkApps.Stop(Seconds(100.));

    Ptr<Socket> ns3UdpSocket = Socket::CreateSocket(c.Get(0), UdpSocketFactory::GetTypeId()); // SourceNode

    // Create UDP application at SourceNode
    Ptr<MyApp> app = CreateObject<MyApp>();
    app->Setup(ns3UdpSocket, sinkAddress, 1040, 100, DataRate("250Kbps")); // Increased packet count to 100
    c.Get(0)->AddApplication(app);
    app->SetStartTime(Seconds(40.));
    app->SetStopTime(Seconds(100.));

    // Set mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0, 200, 0));   // SourceNode
    positionAlloc->Add(Vector(0, 80, 0));    // MaliciousNode1
    positionAlloc->Add(Vector(544, 266, 0)); // MaliciousNode2
    positionAlloc->Add(Vector(520, 526, 0)); // SinkNode
    positionAlloc->Add(Vector(533, 345, 0)); // NormalNode1
    positionAlloc->Add(Vector(0.9, 258, 0)); // NormalNode2
    positionAlloc->Add(Vector(218, 438, 0)); // NormalNode3
    positionAlloc->Add(Vector(175, 700, 0)); // NormalNode4
    positionAlloc->Add(Vector(345, 700, 0)); // NormalNode5
    positionAlloc->Add(Vector(700, 700, 0)); // NormalNode6

    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(c);

    // Setup NetAnim
    AnimationInterface anim("wormhole.xml");
    AnimationInterface::SetConstantPosition(c.Get(0), 0, 200);   // SourceNode
    AnimationInterface::SetConstantPosition(c.Get(1), 0, 80);    // MaliciousNode1
    AnimationInterface::SetConstantPosition(c.Get(2), 544, 266); // MaliciousNode2
    AnimationInterface::SetConstantPosition(c.Get(3), 520, 526); // SinkNode
    AnimationInterface::SetConstantPosition(c.Get(4), 533, 345); // NormalNode1
    AnimationInterface::SetConstantPosition(c.Get(5), 0.9, 258); // NormalNode2
    AnimationInterface::SetConstantPosition(c.Get(6), 218, 438); // NormalNode3
    AnimationInterface::SetConstantPosition(c.Get(7), 100, 360); // NormalNode4
    AnimationInterface::SetConstantPosition(c.Get(8), 349, 485); // NormalNode5
    AnimationInterface::SetConstantPosition(c.Get(9), 700, 700); // NormalNode6

    // Add descriptions for nodes in NetAnim
    anim.UpdateNodeDescription(c.Get(0), "Source");      // SourceNode: Sender of UDP packets
    anim.UpdateNodeDescription(c.Get(1), "Malicious");   // MaliciousNode1: Wormhole attacker
    anim.UpdateNodeDescription(c.Get(2), "Malicious");   // MaliciousNode2: Wormhole attacker
    anim.UpdateNodeDescription(c.Get(3), "Sink");        // SinkNode: Receiver of UDP packets
    anim.UpdateNodeDescription(c.Get(4), "Normal");      // NormalNode1: Regular node
    anim.UpdateNodeDescription(c.Get(5), "Normal");      // NormalNode2: Regular node
    anim.UpdateNodeDescription(c.Get(6), "Normal");      // NormalNode3: Regular node
    anim.UpdateNodeDescription(c.Get(7), "Normal");      // NormalNode4: Regular node
    anim.UpdateNodeDescription(c.Get(8), "Normal");      // NormalNode5: Regular node
    anim.UpdateNodeDescription(c.Get(9), "Normal");      // NormalNode6: Regular node

    anim.EnablePacketMetadata(true);

    // Print routing table
    Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("wormhole.routes", std::ios::out);
    aodv.PrintRoutingTableAllAt(Seconds(45), routingStream);

    // Trace received packets
    Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", 
                                  MakeCallback(&ReceivePacket));

    // Calculate throughput using FlowMonitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    // Run simulation
    NS_LOG_INFO("Run Simulation");
    Simulator::Stop(Seconds(100.0));
    Simulator::Run();

    monitor->CheckForLostPackets();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        if ((t.sourceAddress == not_mal_ifcont.GetAddress(0) && t.destinationAddress == not_mal_ifcont.GetAddress(1)))
        {
            std::cout << "  Flow " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
            std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
            std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
            std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 
                         (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()) / 
                         1024 / 1024 << " Mbps\n";
        }
    }

    monitor->SerializeToXmlFile("lab-4.flowmon", true, true);
}

int main(int argc, char *argv[])
{
    wormhole(argc, argv);
    Simulator::Destroy();
    return 0;
}
