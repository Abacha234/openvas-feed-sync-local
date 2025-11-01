# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886226");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-22871");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:36:28 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for clojure (FEDORA-2024-270cd506bb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-270cd506bb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YFPGUDXMW6OXKIDGCOZFEAXO74VQIB2T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clojure'
  package(s) announced via the FEDORA-2024-270cd506bb advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Clojure is a dynamic programming language that targets the Java
Virtual Machine. It is designed to be a general-purpose language,
combining the approachability and interactive development of a
scripting language with an efficient and robust infrastructure for
multithreaded programming. Clojure is a compiled language - it
compiles directly to JVM bytecode, yet remains completely
dynamic. Every feature supported by Clojure is supported at
runtime. Clojure provides easy access to the Java frameworks, with
optional type hints and type inference, to ensure that calls to Java
can avoid reflection.");

  script_tag(name:"affected", value:"'clojure' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
