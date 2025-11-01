# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66593");
  script_cve_id("CVE-2009-0365");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1955)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1955");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1955");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'network-manager, network-manager-applet' package(s) announced via the DSA-1955 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that network-manager-applet, a network management framework, lacks some dbus restriction rules, which allows local users to obtain sensitive information.

If you have locally modified the /etc/dbus-1/system.d/nm-applet.conf file, then please make sure that you merge the changes from this fix when asked during upgrade.

For the oldstable distribution (etch), this problem has been fixed in version 0.6.4-6+etch1 of network-manager.

For the stable distribution (lenny), this problem has been fixed in version 0.6.6-4+lenny1 of network-manager-applet.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 0.7.0.99-1 of network-manager-applet.

We recommend that you upgrade your network-manager and network-manager-applet packages accordingly.");

  script_tag(name:"affected", value:"'network-manager, network-manager-applet' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);