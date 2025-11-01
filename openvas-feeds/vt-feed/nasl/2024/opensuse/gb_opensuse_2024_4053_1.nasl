# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856739");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21820", "CVE-2024-21853", "CVE-2024-23918", "CVE-2024-23984", "CVE-2024-24968");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-27 05:00:25 +0000 (Wed, 27 Nov 2024)");
  script_name("openSUSE: Security Advisory for ucode (SUSE-SU-2024:4053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4053-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W55XIWF4ZIAHE3T6ORR5YPYWBSK4AFMG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode'
  package(s) announced via the SUSE-SU-2024:4053-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  * Intel CPU Microcode was updated to the 20241112 release (bsc#1233313)

  * CVE-2024-21853: Faulty finite state machines (FSMs) in the hardware logic in
      some 4th and 5th Generation Intel Xeon Processors may allow an authorized
      user to potentially enable denial of service via local access.

  * CVE-2024-23918: Improper conditions check in some Intel Xeon processor
      memory controller configurations when using Intel SGX may allow a privileged
      user to potentially enable escalation of privilege via local access.

  * CVE-2024-21820: Incorrect default permissions in some Intel Xeon processor
      memory controller configurations when using Intel SGX may allow a privileged
      user to potentially enable escalation of privilege via local access.

  * CVE-2024-24968: Improper finite state machines (FSMs) in hardware logic in
      some Intel Processors may allow an privileged user to potentially enable a
      denial of service via local access.

  * CVE-2024-23984: Observable discrepancy in RAPL interface for some Intel
      Processors may allow a privileged user to potentially enable information
      disclosure via local access.

  * Update for functional issues. New Platforms:  Processor  Stepping
      F-M-S/PI  Old Ver  New Ver  Products
      :---------------:---------:------------:---------:---------:---------
      Updated Platforms:  Processor  Stepping  F-M-S/PI  Old Ver  New Ver
      Products
      :---------------:---------:------------:---------:---------:---------
       ADL  C0  06-97-02/07  00000036  00000037  Core Gen12  ADL  H0
      06-97-05/07  00000036  00000037  Core Gen12  ADL  L0  06-9a-03/80
      00000434  00000435  Core Gen12  ADL  R0  06-9a-04/80  00000434
      00000435  Core Gen12  EMR-SP  A0  06-cf-01/87  21000230  21000283
      Xeon Scalable Gen5  EMR-SP  A1  06-cf-02/87  21000230  21000283  Xeon
      Scalable Gen5  MTL  C0  06-aa-04/e6  0000001f  00000020  Core Ultra
      Processor  RPL-H/P/PX 6+8  J0  06-ba-02/e0  00004122  00004123  Core
      Gen13  RPL-HX/S  C0  06-bf-02/07  00000036  00000037  Core Gen13/Gen14
       RPL-S  H0  06-bf-05/07  00000036  00000037  Core Gen13/Gen14  RPL-U
      2+8  Q0  06-ba-03/e0  00004122  00004123  Core Gen13  SPR-SP  E3
      06-8f-06/87  2b0005c0  2b000603  Xeon Scalable Gen4  SPR-SP  E4/S2
      06-8f-07/87  2b0005c0  2b000603  Xeon Scalable Gen4  SPR-SP  E5/S3
      06-8f-08/87  2b0005c0  2b000603  Xeon Scalable Gen4 New Disclosures
      Updated in Prior Releases:  Processor  Stepping  F-M- ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ucode' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
