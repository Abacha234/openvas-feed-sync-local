# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891843");
  script_cve_id("CVE-2019-10162", "CVE-2019-10163");
  script_tag(name:"creation_date", value:"2019-07-04 02:00:08 +0000 (Thu, 04 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 14:27:00 +0000 (Fri, 02 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-1843)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1843");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1843");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pdns");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns' package(s) announced via the DLA-1843 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in pdns, an authoritative DNS server which may result in denial of service via malformed zone records and excessive NOTIFY packets in a master/slave setup.

CVE-2019-10162

An issue has been found in PowerDNS Authoritative Server allowing an authorized user to cause the server to exit by inserting a crafted record in a MASTER type zone under their control. The issue is due to the fact that the Authoritative Server will exit when it runs into a parsing error while looking up the NS/A/AAAA records it is about to use for an outgoing notify.

CVE-2019-10163

An issue has been found in PowerDNS Authoritative Server allowing a remote, authorized master server to cause a high CPU load or even prevent any further updates to any slave zone by sending a large number of NOTIFY messages. Note that only servers configured as slaves are affected by this issue.

For Debian 8 Jessie, these problems have been fixed in version 3.4.1-4+deb8u10.

We recommend that you upgrade your pdns packages.

For the detailed security status of pdns please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);