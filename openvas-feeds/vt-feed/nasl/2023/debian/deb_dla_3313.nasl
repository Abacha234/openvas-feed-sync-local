# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893313");
  script_cve_id("CVE-2022-4345", "CVE-2023-0411", "CVE-2023-0412", "CVE-2023-0413", "CVE-2023-0415", "CVE-2023-0417");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:24 +0000 (Thu, 09 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:50:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-3313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3313");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3313");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-3313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Wireshark, a network traffic analyzer. An attacker could cause a denial of service (infinite loop or application crash) via packet injection or a crafted capture file.

CVE-2022-4345

Infinite loops in the BPv6, OpenFlow, and Kafka protocol dissectors in Wireshark 4.0.0 to 4.0.1 and 3.6.0 to 3.6.9 allows denial of service via packet injection or crafted capture file

CVE-2023-0411

Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

CVE-2023-0412

TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

CVE-2023-0413

Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

CVE-2023-0415

iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

CVE-2023-0417

Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via packet injection or crafted capture file

For Debian 10 buster, these problems have been fixed in version 2.6.20-0+deb10u5.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);