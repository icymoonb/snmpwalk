package snmpwalk;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class snmp {

	private static final int DEFAULT_VERSION = SnmpConstants.version2c;
	private static final String DEFAULT_PROTOCOL = "udp";
	private static final int DEFAULT_PORT = 161;
	private static final long DEFAULT_TIMEOUT = 3 * 1000L;
	private static final int DEFAULT_RETRY = 3;
	private static final String OID_head = "1.3.6.1.2.1.17.4.3.1.";//OID头部

	/**
	 * 创建对象communityTarget
	 *
	 * @param targetAddress
	 * @param community
	 * @param version
	 * @param timeOut
	 * @param retry
	 * @return CommunityTarget
	 */
	public static CommunityTarget createDefault(String ip, String community) {
		Address address = GenericAddress.parse(DEFAULT_PROTOCOL + ":" + ip + "/" + DEFAULT_PORT);
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString(community));
		target.setAddress(address);
		target.setVersion(DEFAULT_VERSION);
		target.setTimeout(DEFAULT_TIMEOUT); // milliseconds
		target.setRetries(DEFAULT_RETRY);
		return target;
	}

	/**
	 * 异步采集信息
	 *
	 * @param ip
	 * @param community
	 * @param oid
	 */
	public static void snmpAsynWalk(String ip, String community, Map<String, FDB> group, int identifier) {
		final CommunityTarget target = createDefault(ip, community);
		Snmp snmp = null;
		try {
			DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
			snmp = new Snmp(transport);
			snmp.listen();

			final PDU pdu = new PDU();
			final OID targetOID = new OID(OID_head+identifier);
			final CountDownLatch latch = new CountDownLatch(1);
			pdu.add(new VariableBinding(targetOID));
			pdu.setType(PDU.GETBULK);
			pdu.setMaxRepetitions(Integer.MAX_VALUE);
			pdu.setNonRepeaters(0);

			ResponseListener listener = new ResponseListener() {
				public void onResponse(ResponseEvent event) {
					((Snmp) event.getSource()).cancel(event.getRequest(), this);

					try {
						PDU response = event.getResponse();
						// PDU request = event.getRequest();
						// System.out.println("[request]:" + request);
						if (response == null) {
							System.out.println("[ERROR]: response is null");
						} else if (response.getErrorStatus() != 0) {
							System.out.println("[ERROR]: response status" + response.getErrorStatus() + " Text:"
									+ response.getErrorStatusText());
						} else {
//							System.out.println("Received Walk response value :");
							VariableBinding vb = response.get(0);
							boolean finished = checkWalkFinished(targetOID, pdu, vb);
							if (!finished) {
//								System.out.println(vb.getOid() + " = " + vb.getVariable());
								String s = vb.getOid().toString();
								s = "*." + s.substring(23, s.length());
								synchronized (group) {
									if (group.containsKey(s)) {
										if (targetOID.toString().equals("1.3.6.1.2.1.17.4.3.1.1")) {// Mac
											group.get(s).setMac(vb.getVariable().toString());
										} else {// Port
											group.get(s).setPort(vb.getVariable().toString());
										}
									} else {
										if (targetOID.toString().equals("1.3.6.1.2.1.17.4.3.1.1")) {// Mac
											FDB data = new FDB();
											data.setMac(vb.getVariable().toString());
											group.put(s, data);
										} else {// Port
											FDB data = new FDB();
											data.setPort(vb.getVariable().toString());
											group.put(s, data);
										}
									}
								}
								pdu.setRequestID(new Integer32(0));
								pdu.set(0, vb);
								((Snmp) event.getSource()).getNext(pdu, target, null, this);
							} else {
//								System.out.println("SNMP Asyn walk OID value success !");
								latch.countDown();
							}
						}
					} catch (Exception e) {
						e.printStackTrace();
						latch.countDown();
					}

				}
			};

			snmp.getNext(pdu, target, null, listener);
//			System.out.println("pdu 已发送,等到异步处理结果...");

			boolean wait = latch.await(30, TimeUnit.SECONDS);
//			System.out.println("latch.await =:" + wait);
			snmp.close();

//			System.out.println("----> demo end <----");
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("SNMP Asyn Walk Exception:" + e);
		}

	}

	private static boolean checkWalkFinished(OID walkOID, PDU pdu, VariableBinding vb) {
		boolean finished = false;
		if (pdu.getErrorStatus() != 0) {
//			System.out.println("[true] pdu.getErrorStatus() != 0 ");
//			System.out.println(pdu.getErrorStatusText());
			finished = true;
		} else if (vb.getOid() == null) {
//			System.out.println("[true] vb.getOid() == null");
			finished = true;
		} else if (vb.getOid().size() < walkOID.size()) {
//			System.out.println("[true] vb.getOid().size() < targetOID.size()");
			finished = true;
		} else if (walkOID.leftMostCompare(walkOID.size(), vb.getOid()) != 0) {
//			System.out.println("[true] targetOID.leftMostCompare() != 0");
			finished = true;
		} else if (Null.isExceptionSyntax(vb.getVariable().getSyntax())) {
//			System.out.println("[true] Null.isExceptionSyntax(vb.getVariable().getSyntax())");
			finished = true;
		} else if (vb.getOid().compareTo(walkOID) <= 0) {
//			System.out.println("[true] vb.getOid().compareTo(walkOID) <= 0 ");
			finished = true;
		}
		return finished;

	}

	/**
	 * 主方法
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		String elements[] = new String[4];
		boolean inputCheck = false;
		while (!inputCheck) {
			String str = readDataFromConsole();
//			String str = "snmpwalk -c broadapublic -v2c 10.1.1.51";
			inputCheck = checkInput(str, elements);
		}
		String ip = elements[3];
		String community = elements[1];
		Map<String, FDB> group = new HashMap<String, FDB>();
		snmp.snmpAsynWalk(ip, community, group, 1);//采集Mac
		snmp.snmpAsynWalk(ip, community, group, 2);//采集Port
		printResult(group);
	}
	
	private static String readDataFromConsole() {  
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));  
        String str = null;  
        try {  
            System.out.println("PLEASE INPUT COMMAND");
            System.out.println("example：snmpwalk -c broadapublic -v2c 10.1.1.51");
            System.out.println("======================>");
            str = br.readLine();  
  
        } catch (IOException e) {
            e.printStackTrace();  
        }  
        return str;  
    }
	
	private static void printResult(Map<String, FDB> group) {  
		System.out.println("Total records = " + group.size());
		System.out.println("===========iso======================mac==========port=");
		for (String head : group.keySet()) {
			String head_format = head;
			if(head_format.length()<26){
				while (head_format.length()<26) {
					head_format += " ";
				}
			}
			FDB fdb = group.get(head);
			if(fdb.getMac()!="null")
				System.out.println(head_format + " | " + fdb.getMac() + " |  " + fdb.getPort());
			else {
				System.out.println(head_format + " |                   |  " + fdb.getPort());
			}
		}
		System.out.println("===========iso======================mac==========port=");
    }
	
	private static boolean checkInput(String str, String elements[]) throws Exception {
		try {
			String strFormat = str.replaceAll(" ", "");
			// command elements[0]
			if (!strFormat.substring(0, 8).equals("snmpwalk")) {
				System.err.println("can't find command: " + str.split(" ")[0]);
				return false;
			} else {
				elements[0] = "snmpwalk";
			}
			// community elements[1]
			if (!strFormat.split("-")[1].substring(0, 1).equals("c")) {
				System.err.println("can't find element: -" + strFormat.split("-")[1].substring(0, 1));
				return false;
			} else {
				elements[1] = strFormat.split("-")[1].substring(1, strFormat.split("-")[1].length());
			}
			// version elements[2]
			if (!strFormat.split("-")[2].substring(0, 1).equals("v")) {
				System.err.println("can't find element: -" + strFormat.split("-")[2].substring(0, 1));
				return false;
			} else {
				if (strFormat.split("-")[2].contains("c")) {
					if (!strFormat.split("-")[2].substring(1, 3).equals("2c")) {
						return false;
					}
					elements[2] = "2c";
				} else {
					elements[2] = strFormat.split("-")[2].substring(1, 2);
				}
			}
			// IP elements[3]
			while (str.contains("  ")) {
				str.replaceAll("  ", " ");
			}
			if (!str.split(" ")[str.split(" ").length - 1].matches(
					"([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}")) {
				System.err.println("can't find command: " + str.split(" ")[str.split(" ").length - 1]);
				return false;
			} else {
				elements[3] = str.split(" ")[str.split(" ").length - 1];
			}
			return true;
		} catch (Exception e) {
			System.err.println("typing error");
		}
		return false;
	}
}
