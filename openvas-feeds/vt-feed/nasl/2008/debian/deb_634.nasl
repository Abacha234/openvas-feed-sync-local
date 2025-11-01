# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53470");
  script_cve_id("CVE-2004-1182");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-634)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-634");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-634");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hylafax' package(s) announced via the DSA-634 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Patrice Fournier discovered a vulnerability in the authorisation subsystem of hylafax, a flexible client/server fax system. A local or remote user guessing the contents of the hosts.hfaxd database could gain unauthorised access to the fax system.

Some installations of hylafax may actually utilise the weak hostname and username validation for authorized uses. For example, hosts.hfaxd entries that may be common are

192.168.0 username:uid:pass:adminpass user@host

After updating, these entries will need to be modified in order to continue to function. Respectively, the correct entries should be

192.168.0.[0-9]+ username@:uid:pass:adminpass user@host

Unless such matching of 'username' with 'otherusername' and 'host' with 'hostname' is desired, the proper form of these entries should include the delimiter and markers like this

@192.168.0.[0-9]+$ ^username@:uid:pass:adminpass ^user@host$

For the stable distribution (woody) this problem has been fixed in version 4.1.1-3.1.

For the unstable distribution (sid) this problem has been fixed in version 4.2.1-1.

We recommend that you upgrade your hylafax packages.");

  script_tag(name:"affected", value:"'hylafax' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);