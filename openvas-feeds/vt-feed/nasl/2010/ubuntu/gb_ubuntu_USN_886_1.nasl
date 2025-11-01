# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840370");
  script_cve_id("CVE-2008-2955", "CVE-2009-1376", "CVE-2009-2703", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3085", "CVE-2009-3615", "CVE-2010-0013");
  script_tag(name:"creation_date", value:"2010-01-20 08:25:19 +0000 (Wed, 20 Jan 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-886-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-886-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-886-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the USN-886-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pidgin did not properly handle certain topic
messages in the IRC protocol handler. If a user were tricked into
connecting to a malicious IRC server, an attacker could cause Pidgin to
crash, leading to a denial of service. This issue only affected Ubuntu 8.04
LTS, Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-2703)

It was discovered that Pidgin did not properly enforce the 'require
TLS/SSL' setting when connecting to certain older Jabber servers. If a
remote attacker were able to perform a machine-in-the-middle attack, this flaw
could be exploited to view sensitive information. This issue only affected
Ubuntu 8.04 LTS, Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-3026)

It was discovered that Pidgin did not properly handle certain SLP invite
messages in the MSN protocol handler. A remote attacker could send a
specially crafted invite message and cause Pidgin to crash, leading to a
denial of service. This issue only affected Ubuntu 8.04 LTS, Ubuntu 8.10
and Ubuntu 9.04. (CVE-2009-3083)

It was discovered that Pidgin did not properly handle certain errors in the
XMPP protocol handler. A remote attacker could send a specially crafted
message and cause Pidgin to crash, leading to a denial of service. This
issue only affected Ubuntu 8.10 and Ubuntu 9.04. (CVE-2009-3085)

It was discovered that Pidgin did not properly handle malformed
contact-list data in the OSCAR protocol handler. A remote attacker could
send specially crafted contact-list data and cause Pidgin to crash, leading
to a denial of service. (CVE-2009-3615)

It was discovered that Pidgin did not properly handle custom smiley
requests in the MSN protocol handler. A remote attacker could send a
specially crafted filename in a custom smiley request and obtain arbitrary
files via directory traversal. This issue only affected Ubuntu 8.10, Ubuntu
9.04 and Ubuntu 9.10. (CVE-2010-0013)

Pidgin for Ubuntu 8.04 LTS was also updated to fix connection issues with
the MSN protocol.

USN-675-1 and USN-781-1 provided updated Pidgin packages to fix multiple
security vulnerabilities in Ubuntu 8.04 LTS. The security patches to fix
CVE-2008-2955 and CVE-2009-1376 were incomplete. This update corrects the
problem. Original advisory details:

 It was discovered that Pidgin did not properly handle file transfers
 containing a long filename and special characters in the MSN protocol
 handler. A remote attacker could send a specially crafted filename in a
 file transfer request and cause Pidgin to crash, leading to a denial of
 service. (CVE-2008-2955)

 It was discovered that Pidgin did not properly handle certain malformed
 messages in the MSN protocol handler. A remote attacker could send a
 specially crafted message and possibly execute arbitrary code with user
 privileges. (CVE-2009-1376)");

  script_tag(name:"affected", value:"'pidgin' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
