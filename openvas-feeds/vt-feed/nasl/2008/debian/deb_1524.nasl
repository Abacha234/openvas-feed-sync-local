# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60578");
  script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1524)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1524");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1524");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-1524 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the kdc component of the krb5, a system for authenticating users and services on a network. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0062

An unauthenticated remote attacker may cause a krb4-enabled KDC to crash, expose information, or execute arbitrary code. Successful exploitation of this vulnerability could compromise the Kerberos key database and host security on the KDC host.

CVE-2008-0063

An unauthenticated remote attacker may cause a krb4-enabled KDC to expose information. It is theoretically possible for the exposed information to include secret key data on some platforms.

CVE-2008-0947

An unauthenticated remote attacker can cause memory corruption in the kadmind process, which is likely to cause kadmind to crash, resulting in a denial of service. It is at least theoretically possible for such corruption to result in database corruption or arbitrary code execution, though we have no such exploit and are not aware of any such exploits in use in the wild. In versions of MIT Kerberos shipped by Debian, this bug can only be triggered in configurations that allow large numbers of open file descriptors in a process.

For the old stable distribution (sarge), these problems have been fixed in version krb5 1.3.6-2sarge6.

For the stable distribution (etch), these problems have been fixed in version 1.4.4-7etch5.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);