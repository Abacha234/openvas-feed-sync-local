# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841494");
  script_cve_id("CVE-2012-4929");
  script_tag(name:"creation_date", value:"2013-07-05 07:46:50 +0000 (Fri, 05 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1898-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1898-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-1898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The TLS protocol 1.2 and earlier can encrypt compressed data without
properly obfuscating the length of the unencrypted data, which allows
machine-in-the-middle attackers to obtain plaintext content by observing
length differences during a series of guesses in which a provided string
potentially matches an unknown string in encrypted and compressed traffic.
This is known as a CRIME attack in HTTP. Other protocols layered on top of
TLS may also make these attacks practical.

This update disables compression for all programs using SSL and TLS
provided by the OpenSSL library. To re-enable compression for programs
that need compression to communicate with legacy services, define the
variable OPENSSL_DEFAULT_ZLIB in the program's environment.");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
