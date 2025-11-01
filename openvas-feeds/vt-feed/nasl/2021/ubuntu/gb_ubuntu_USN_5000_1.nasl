# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844985");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-31829", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3506", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-06-24 03:00:23 +0000 (Thu, 24 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 08:15:00 +0000 (Tue, 06 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5000-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5000-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-5000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code. (CVE-2021-3609)

Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly enforce limits for pointer operations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-33200)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation did
not properly clear received fragments from memory in some situations. A
physically proximate attacker could possibly use this issue to inject
packets or expose sensitive information. (CVE-2020-24586)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled encrypted fragments. A physically proximate attacker
could possibly use this issue to decrypt fragments. (CVE-2020-24587)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled certain malformed frames. If a user were tricked into
connecting to a malicious server, a physically proximate attacker could use
this issue to inject packets. (CVE-2020-24588)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled EAPOL frames from unauthenticated senders. A physically
proximate attacker could inject malicious packets to cause a denial of
service (system crash). (CVE-2020-26139)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation did
not properly verify certain fragmented frames. A physically proximate
attacker could possibly use this issue to inject or decrypt packets.
(CVE-2020-26141)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
accepted plaintext fragments in certain situations. A physically proximate
attacker could use this issue to inject packets. (CVE-2020-26145)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation could
reassemble mixed encrypted and plaintext fragments. A physically proximate
attacker could possibly use this issue to inject packets or exfiltrate
selected fragments. (CVE-2020-26147)

Or Cohen discovered that the SCTP implementation in the Linux kernel
contained a race condition in some situations, leading to a use-after-free
condition. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-23133)

Or Cohen and Nadav Markus discovered a use-after-free vulnerability in the
nfc implementation in the Linux kernel. A privileged local attacker could
use this issue to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-23134)

Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly prevent speculative loads in certain situations. A local
attacker could use this ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
