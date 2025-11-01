# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844010");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16884", "CVE-2019-11091", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-3887", "CVE-2019-9500", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2019-05-15 02:03:11 +0000 (Wed, 15 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:00 +0000 (Wed, 29 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-3980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3980-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3980-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/MDS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-raspi2, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp' package(s) announced via the USN-3980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi Maisuradze, Dan
Horea Lutas, Andrei Lutas, Volodymyr Pikhur, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos,
Cristiano Giuffrida, Moritz Lipp, Michael Schwarz, and Daniel Gruss
discovered that memory previously stored in microarchitectural fill buffers
of an Intel CPU core may be exposed to a malicious process that is
executing on the same CPU core. A local attacker could use this to expose
sensitive information. (CVE-2018-12130)

Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Stephan
van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh
Razavi, Herbert Bos, and Cristiano Giuffrida discovered that memory
previously stored in microarchitectural load ports of an Intel CPU core may
be exposed to a malicious process that is executing on the same CPU core. A
local attacker could use this to expose sensitive information.
(CVE-2018-12127)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin, Daniel
Moghimi, Moritz Lipp, Michael Schwarz, Jo Van Bulck, Daniel Genkin, Daniel
Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom discovered that memory
previously stored in microarchitectural store buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same CPU
core. A local attacker could use this to expose sensitive information.
(CVE-2018-12126)

Vasily Averin and Evgenii Shatokhin discovered that a use-after-free
vulnerability existed in the NFS41+ subsystem when multiple network
namespaces are in use. A local attacker in a container could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-16884)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos, and
Cristiano Giuffrida discovered that uncacheable memory previously stored in
microarchitectural buffers of an Intel CPU core may be exposed to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11091)

Matteo Croce, Natale Vinto, and Andrea Spagnolo discovered that the cgroups
subsystem of the Linux kernel did not properly account for SCTP socket
buffers. A local attacker could use this to cause a denial of service
(system crash). (CVE-2019-3874)

Alex Williamson discovered that the vfio subsystem of the Linux kernel did
not properly limit DMA mappings. A local attacker could use this to cause a
denial of service (memory exhaustion). (CVE-2019-3882)

Marc Orr discovered that the KVM hypervisor implementation in the Linux
kernel did not properly restrict APIC MSR register values when nested
virtualization is used. An attacker in a guest vm could use this to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-raspi2, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp' package(s) on Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
