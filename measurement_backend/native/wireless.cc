/* ns-3 3.44 IEEE 802.11p broadcast experiment. No PC5 claim.
 * Input: waypoint CSV(node,time_us,x,y), traffic CSV(index,time_us,node,bytes).
 * Output: all sends and actual receiver deliveries with simulated timestamps.
 */
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include <fstream>
#include <sstream>
#include <map>
using namespace ns3;
static std::ofstream output;
static std::map<uint64_t,uint64_t> indexes;
static bool Receive(Ptr<NetDevice>,Ptr<const Packet> packet,uint16_t,const Address&) {
    auto it=indexes.find(packet->GetUid());
    if(it!=indexes.end())output<<it->second<<",rx,"<<Simulator::Now().GetMicroSeconds()<<"\n";
    return true;
}
static void Transmit(Ptr<NetDevice> device,uint64_t index,uint32_t bytes) {
    auto packet=Create<Packet>(bytes);indexes[packet->GetUid()]=index;
    bool ok=device->Send(packet,device->GetBroadcast(),0x88b5);
    output<<index<<(ok?",tx,":",tx_reject,")<<Simulator::Now().GetMicroSeconds()<<"\n";
}
int main(int argc,char **argv) {
    std::string positions,traffic,out;uint32_t vehicles=1,seed=1;double txPower=16,exponent=2.7;
    CommandLine cmd;cmd.AddValue("positions","waypoints",positions);cmd.AddValue("traffic","traffic",traffic);
    cmd.AddValue("out","events",out);cmd.AddValue("vehicles","vehicles",vehicles);cmd.AddValue("seed","seed",seed);
    cmd.AddValue("txPower","dBm",txPower);cmd.AddValue("exponent","log-distance exponent",exponent);cmd.Parse(argc,argv);
    RngSeedManager::SetSeed(seed);RngSeedManager::SetRun(1);
    NodeContainer nodes;nodes.Create(vehicles+1);
    auto rsu=CreateObject<ConstantPositionMobilityModel>();rsu->SetPosition(Vector(200,200,3));nodes.Get(0)->AggregateObject(rsu);
    for(uint32_t n=1;n<=vehicles;n++)nodes.Get(n)->AggregateObject(CreateObject<WaypointMobilityModel>());
    std::ifstream pos(positions);std::string line;double last=0;
    if(!pos.is_open())return 2;
    while(std::getline(pos,line)) {
        std::replace(line.begin(),line.end(),',',' ');std::istringstream row(line);uint32_t n;uint64_t us;double x,y;
        if(!(row>>n>>us>>x>>y) || n==0 || n>vehicles)return 3;
        nodes.Get(n)->GetObject<WaypointMobilityModel>()->AddWaypoint(Waypoint(MicroSeconds(us),Vector(x,y,1.5)));
        last=std::max(last,us/1e6);
    }
    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel","Exponent",DoubleValue(exponent),
                              "ReferenceDistance",DoubleValue(1),"ReferenceLoss",DoubleValue(47.86));
    YansWifiPhyHelper phy;phy.SetChannel(channel.Create());
    phy.Set("TxPowerStart",DoubleValue(txPower));phy.Set("TxPowerEnd",DoubleValue(txPower));
    phy.Set("ChannelSettings",StringValue("{172, 10, BAND_5GHZ, 0}"));
    WifiHelper wifi;wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager","DataMode",StringValue("OfdmRate6MbpsBW10MHz"),
                                  "ControlMode",StringValue("OfdmRate6MbpsBW10MHz"));
    WifiMacHelper mac;mac.SetType("ns3::AdhocWifiMac");
    auto devices=wifi.Install(phy,mac,nodes);wifi.AssignStreams(devices,100);
    devices.Get(0)->SetReceiveCallback(MakeCallback(&Receive));
    std::ifstream messages(traffic);if(!messages.is_open())return 4;
    while(std::getline(messages,line)) {
        std::replace(line.begin(),line.end(),',',' ');std::istringstream row(line);uint64_t index,us;uint32_t n,bytes;
        if(!(row>>index>>us>>n>>bytes) || n==0 || n>vehicles || bytes<1)return 5;
        Simulator::Schedule(MicroSeconds(us),&Transmit,devices.Get(n),index,bytes);last=std::max(last,us/1e6);
    }
    output.open(out);output<<"index,event,time_us\n";
    Simulator::Stop(Seconds(last+1));Simulator::Run();Simulator::Destroy();output.close();return 0;
}
