# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703190");
  script_cve_id("CVE-2015-2157");
  script_tag(name:"creation_date", value:"2015-03-14 23:00:00 +0000 (Sat, 14 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3190");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3190");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'putty' package(s) announced via the DSA-3190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Patrick Coleman discovered that the Putty SSH client failed to wipe out unused sensitive memory.

In addition Florent Daigniere discovered that exponential values in Diffie Hellman exchanges were insufficienty restricted.

For the stable distribution (wheezy), this problem has been fixed in version 0.62-9+deb7u2.

For the upcoming stable distribution (jessie), this problem has been fixed in version 0.63-10.

For the unstable distribution (sid), this problem has been fixed in version 0.63-10.

We recommend that you upgrade your putty packages.");

  script_tag(name:"affected", value:"'putty' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);