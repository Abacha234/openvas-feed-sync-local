# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844308");
  script_tag(name:"creation_date", value:"2020-01-24 04:00:22 +0000 (Fri, 24 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4233-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4233-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4233-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1860656");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-4233-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4233-1 disabled SHA1 being used for digital signature operations in
GnuTLS. In certain network environments, certificates using SHA1 may still
be in use. This update adds the %VERIFY_ALLOW_BROKEN and
%VERIFY_ALLOW_SIGN_WITH_SHA1 priority strings that can be used to
temporarily re-enable SHA1 until certificates can be replaced with a
stronger algorithm.

Original advisory details:

 As a security improvement, this update marks SHA1 as being untrusted for
 digital signature operations.");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
