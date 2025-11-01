# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702669");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0160", "CVE-2013-1796", "CVE-2013-1929", "CVE-2013-1979", "CVE-2013-2015", "CVE-2013-2094", "CVE-2013-2141", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-3301");
  script_tag(name:"creation_date", value:"2013-05-14 22:00:00 +0000 (Tue, 14 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2669)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2669");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2669");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-2669 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, information leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-0160

vladz reported a timing leak with the /dev/ptmx character device. A local user could use this to determine sensitive information such as password length.

CVE-2013-1796

Andrew Honig of Google reported an issue in the KVM subsystem. A user in a guest operating system could corrupt kernel memory, resulting in a denial of service.

CVE-2013-1929

Oded Horovitz and Brad Spengler reported an issue in the device driver for Broadcom Tigon3 based gigabit Ethernet. Users with the ability to attach untrusted devices can create an overflow condition, resulting in a denial of service or elevated privileges.

CVE-2013-1979

Andy Lutomirski reported an issue in the socket level control message processing subsystem. Local users may be able to gain eleveated privileges.

CVE-2013-2015

Theodore Ts'o provided a fix for an issue in the ext4 filesystem. Local users with the ability to mount a specially crafted filesystem can cause a denial of service (infinite loop).

CVE-2013-2094

Tommie Rantala discovered an issue in the perf subsystem. An out-of-bounds access vulnerability allows local users to gain elevated privileges.

CVE-2013-3076

Mathias Krause discovered an issue in the userspace interface for hash algorithms. Local users can gain access to sensitive kernel memory.

CVE-2013-3222

Mathias Krause discovered an issue in the Asynchronous Transfer Mode (ATM) protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3223

Mathias Krause discovered an issue in the Amateur Radio AX.25 protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3224

Mathias Krause discovered an issue in the Bluetooth subsystem. Local users can gain access to sensitive kernel memory.

CVE-2013-3225

Mathias Krause discovered an issue in the Bluetooth RFCOMM protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3227

Mathias Krause discovered an issue in the Communication CPU to Application CPU Interface (CAIF). Local users can gain access to sensitive kernel memory.

CVE-2013-3228

Mathias Krause discovered an issue in the IrDA (infrared) subsystem support. Local users can gain access to sensitive kernel memory.

CVE-2013-3229

Mathias Krause discovered an issue in the IUCV support on s390 systems. Local users can gain access to sensitive kernel memory.

CVE-2013-3231

Mathias Krause discovered an issue in the ANSI/IEEE 802.2 LLC type 2 protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3234

Mathias Krause discovered an issue in the Amateur Radio X.25 PLP (Rose) protocol support. Local users can gain access to sensitive kernel ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);