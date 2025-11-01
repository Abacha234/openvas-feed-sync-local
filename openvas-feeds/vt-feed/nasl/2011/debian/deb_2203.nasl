# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69339");
  script_version("2023-06-28T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2203-1 (nss)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202203-1");
  script_tag(name:"insight", value:"This update for the Network Security Service libraries marks several
fraudulent HTTPS certificates as unstrusted.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 3.12.9.with.ckbi.1.82-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your nss packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to nss
announced via advisory DSA 2203-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
