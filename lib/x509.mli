(** X509 encoding, generation, and validation.

    [X509] is a module for handling X.509 certificates and supplementary
   material (such as public and private RSA keys), as described in
   {{:https://tools.ietf.org/html/rfc5280}RFC 5280}.  X.509 describes a
   hierarchical public key infrastructure, where all trust is delegated to
   certificate authorities (CA).  The task of a CA is to sign certificate
   signing requests (CSR), which turns them into certificates, after
   verification that the requestor is eligible.

    An X.509 certificate is an authentication token: a public key, a subject
   (e.g. server name), a validity period, optionally a purpose (usage), and
   various other optional {{!Extension}Extensions}.

    The public keys of trusted CAs are distributed with the software, or
   configured manually.  When an endpoint connects, it presents its
   certificate chain, which are pairwise signed certificates.  This chain is
   verified: the signatures have to be valid, the last certificate must be
   signed by a trusted CA, the name has to match the expected name, all
   certificates must be valid at the current time, and the purpose of each
   certificate must match its usage.  An alternative validator checks that the
   hash of the server certificate matches the given hash.

    This module uses the [result] type for errors. No provided binging raises
   an exception. Provided submodules include decoders and encoders (ASN.1 DER
   and PEM encoding) of X.509v3 {{!Certificate}certificates},
   {{!Distinguished_name}distinguished names}, {{!Public_key}public keys} and
   {{!Private_key}private keys}
   ({{:http://tools.ietf.org/html/rfc5208}PKCS 8, RFC 5208}), and
   {{!Signing_request}certificate signing requests}
   ({{:http://tools.ietf.org/html/rfc2986}PKCS 10, RFC 2986},
   both use parts of
   {{:https://tools.ietf.org/html/rfc2985}PKCS 9, RFC 2985}),
   {{!Validation} certificate validation} by construction of
   {{!Authenticator} authenticators}.  Name validation, as defined in
   {{:https://tools.ietf.org/html/rfc6125}RFC 6125}, is also implemented.

    Missing is the handling of online certificate status protocol. Some X.509v3
   extensions are not handled, but only parsed, such as name constraints. If any
   extension is marked as critical in a certificate, but not handled, the
   validation will fail. The only supported key type is RSA.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

open Rresult

(** RSA public key DER and PEM encoding and decoding *)
module Public_key : sig
  (** Public keys as specified in {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
      are supported in this module, mainly RSA. *)

  (** The polymorphic variant of public keys, with
      {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
      {{!Encoding.Pem.Public_key}encoding and decoding to PEM}. *)
  type t = [ `RSA of Nocrypto.Rsa.pub | `EC_pub of Asn.oid ]

  (** [id public_key] is [digest], the 160-bit [`SHA1] hash of the BIT
      STRING subjectPublicKey (excluding tag, length, and number of
      unused bits) for publicKeyInfo of [public_key].

      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.2}RFC 5280, 4.2.1.2, variant (1)} *)
  val id: t -> Cstruct.t

  (** [fingerprint ?hash public_key] is [digest], the hash (by
      default SHA256) of the DER encoded public key (equivalent to
      [openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -HASH]).  *)
  val fingerprint : ?hash:Nocrypto.Hash.hash -> t -> Cstruct.t

  (** {1 Decoding and encoding in ASN.1 DER and PEM format} *)

  (** [encode_der pk] is [buffer], the ASN.1 encoding of the given public key. *)
  val encode_der : t -> Cstruct.t

  (** [decode_der buffer] is [pubkey], the public key of the ASN.1 encoded buffer. *)
  val decode_der : Cstruct.t -> (t, [> R.msg ]) result

  (** [decode_pem pem] is [t], where the public key of [pem] is extracted *)
  val decode_pem : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_pem public_key] is [pem], the pem encoded public key. *)
  val encode_pem : t -> Cstruct.t
end

(** RSA private key pem encoding and decoding *)
module Private_key : sig
  (** RSA private keys as defined in
      {{:http://tools.ietf.org/html/rfc5208}PKCS 8}: decoding and encoding
      in PEM format  *)

  (** The polymorphic variant of private keys. *)
  type t = [ `RSA of Nocrypto.Rsa.priv ]

  (** [decode_pem pem] is [t], where the private key of [pem] is extracted.
      Both RSA PRIVATE KEY and PRIVATE KEY stanzas are supported. *)
  val decode_pem : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_pem key] is [pem], the encoded private key (using [PRIVATE KEY]). *)
  val encode_pem : t -> Cstruct.t
end

(** X.500 distinguished name *)
module Distinguished_name : sig

  (** The variant of a relative distinguished name component, as defined in
    X.500: an attribute type and value. *)
  type attribute =
    | CN of string
    | Serialnumber of string
    | C of string
    | L of string
    | SP of string
    | O of string
    | OU of string
    | T of string
    | DNQ of string
    | Mail of string
    | DC of string
    | Given_name of string
    | Surname of string
    | Initials of string
    | Pseudonym of string
    | Generation of string
    | Other of Asn.oid * string

  (** Relative_distinguished_name is a set of attributes. *)
  module Relative_distinguished_name : Set.S with type elt = attribute

  (** A distinguished name is a list of relative distinguished names, starting
      with the most significant component. *)
  type t = Relative_distinguished_name.t list

  (** [equal a b] is [true] if the distinguished names [a] and [b] are equal. *)
  val equal : t -> t -> bool

  (** [make_pp ?style ()] creates a customized pretty-printer where [style] is
      one of:

        - [`RFC_comma], [`RFC_semi] produces the
          {{:https://tools.ietf.org/html/rfc5280}RFC4514} (or later) format
          using comma or semicolon followed by a cut as RDN separator.
        - [`RFC_comma_sp] and [`RFC_semi_sp] acts like [`RFC] and [`RFC_semi]
          but with space break hints instead of cuts.
        - [`OSF] emits RDNs prefixed by slashes and separated by cuts in
          most-significant to least-significat order. This format is designed by
          analogy to RFC4514, and may not be fully compliant to the OSF
          specifications, if it exists.

      The pretty-printer can be wrapped in a box to control line breaking and
      set it apart, otherwise the RDN componets will flow with the surrounding
      text. *)
  val make_pp :
    ?style: [`RFC_comma | `RFC_comma_sp | `RFC_semi | `RFC_semi_sp | `OSF] ->
    unit -> t Fmt.t

  (** [pp ppf dn] pretty-prints the distinguished name. This is the default
      pretty-printer generated by {!make_pp} wrapped in [Fmt.hbox], which
      produces an {{:https://tools.ietf.org/html/rfc5280}RFC4514} DN using comma
      as RDN separator with no extra spaces or line breaks. If your application
      relies on the precise format, it is advicable to create a custom formatter
      with {!make_pp} to guard against future changes to the default format. *)
  val pp : t Fmt.t

  (** [decode_der cs] is [dn], the ASN.1 decoded distinguished name of [cs]. *)
  val decode_der : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_der dn] is [cstruct], the ASN.1 encoded representation of the
      distinguished name [dn]. *)
  val encode_der : t -> Cstruct.t
end

(** A list of [general_name]s is the value of both
    {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}subjectAltName}
    and
    {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.7}IssuerAltName}
    extension. *)
module General_name : sig
  type _ k =
    | Other : Asn.oid -> string list k
    | Rfc_822 : string list k
    | DNS : string list k
    | X400_address : unit k
    | Directory : Distinguished_name.t list k
    | EDI_party : (string option * string) list k
    | URI : string list k
    | IP : Cstruct.t list k
    | Registered_id : Asn.oid list k

  include Gmap.S with type 'a key = 'a k

  val pp : t Fmt.t
end


(** X.509v3 extensions *)
module Extension : sig

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.3}key usages}. *)
  type key_usage = [
    | `Digital_signature
    | `Content_commitment
    | `Key_encipherment
    | `Data_encipherment
    | `Key_agreement
    | `Key_cert_sign
    | `CRL_sign
    | `Encipher_only
    | `Decipher_only
  ]

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.12}extended key usages}. *)
  type extended_key_usage = [
    | `Any
    | `Server_auth
    | `Client_auth
    | `Code_signing
    | `Email_protection
    | `Ipsec_end
    | `Ipsec_tunnel
    | `Ipsec_user
    | `Time_stamping
    | `Ocsp_signing
    | `Other of Asn.oid
  ]

  (** The authority key identifier, as present in the
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.1}Authority Key Identifier}
      extension. *)
  type authority_key_id = Cstruct.t option * General_name.t * Z.t option

  (** The private key usage period, as defined in
      {{:https://tools.ietf.org/html/rfc3280#section-4.2.1.4}RFC 3280}. *)
  type priv_key_usage_period = [
    | `Interval   of Ptime.t * Ptime.t
    | `Not_after  of Ptime.t
    | `Not_before of Ptime.t
  ]

  (** Name constraints, as defined in
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.10}RFC 5280}. *)
  type name_constraint = (General_name.b * int * int option) list

  (** Certificate policies, the
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.4}policy extension}. *)
  type policy = [ `Any | `Something of Asn.oid ]

  (** Type of
      {{:https://tools.ietf.org/html/rfc5280#section-5.3.1}revocation reasons}
      for a given distribution point. *)
  type reason = [
    | `Unspecified
    | `Key_compromise
    | `CA_compromise
    | `Affiliation_changed
    | `Superseded
    | `Cessation_of_operation
    | `Certificate_hold
    | `Remove_from_CRL
    | `Privilege_withdrawn
    | `AA_compromise
  ]

  (** Distribution point name, either a full one using general names, or a
      relative one using a distinguished name. *)
  type distribution_point_name =
    [ `Full of General_name.t
    | `Relative of Distinguished_name.t ]

  (** {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.13}Distribution point},
      consisting of an optional name, an optional list of allowed reasons, and
      an optional issuer. *)
  type distribution_point =
    distribution_point_name option *
    reason list option *
    General_name.t option

  (** The type of an extension: the critical flag and the value itself. *)
  type 'a extension = bool * 'a

  (** The type of supported
      {{:https://tools.ietf.org/html/rfc5280#section-4.2}X509v3} and
      {{:https://tools.ietf.org/html/rfc5280#section-5.2}CRL} extensions. *)
  type _ k =
    | Unsupported : Asn.oid -> Cstruct.t extension k
    | Subject_alt_name : General_name.t extension k
    | Authority_key_id : authority_key_id extension k
    | Subject_key_id : Cstruct.t extension k
    | Issuer_alt_name : General_name.t extension k
    | Key_usage : key_usage list extension k
    | Ext_key_usage : extended_key_usage list extension k
    | Basic_constraints : (bool * int option) extension k
    | CRL_number : int extension k
    | Delta_CRL_indicator : int extension k
    | Priv_key_period : priv_key_usage_period extension k
    | Name_constraints : (name_constraint * name_constraint) extension k
    | CRL_distribution_points : distribution_point list extension k
    | Issuing_distribution_point : (distribution_point_name option * bool * bool * reason list option * bool * bool) extension k
    | Freshest_CRL : distribution_point list extension k
    | Reason : reason extension k
    | Invalidity_date : Ptime.t extension k
    | Certificate_issuer : General_name.t extension k
    | Policies : policy list extension k

  include Gmap.S with type 'a key = 'a k

  (** [critical ext_key ext_value] is the critical bit in [ext_value]. *)
  val critical : 'a key -> 'a -> bool

  (** [pp ppf ext_map] pretty-prints the extension map. *)
  val pp : t Fmt.t
end

(** X509v3 certificate *)
module Certificate : sig

  (** [decode_pkcs1_digest_info buffer] is [hash, signature], the hash and raw
      signature of the given [buffer] in ASN.1 DER encoding, or an error. *)
  val decode_pkcs1_digest_info : Cstruct.t ->
    (Nocrypto.Hash.hash * Cstruct.t, [> R.msg ]) result

  (** [encode_pkcs1_digest_info (hash, signature)] is [data], the ASN.1 DER
      encoded hash and signature. *)
  val encode_pkcs1_digest_info : Nocrypto.Hash.hash * Cstruct.t -> Cstruct.t

  (** {1 Abstract certificate type} *)

  (** The abstract type of a certificate. *)
  type t

  (** [pp ppf cert] pretty-prints the certificate. *)
  val pp : t Fmt.t

  (** {1 Encoding and decoding in ASN.1 DER and PEM format} *)

  (** [decode_der cstruct] is [certificate], the ASN.1 decoded [certificate]
      or an error. *)
  val decode_der : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_der certificate] is [cstruct], the ASN.1 encoded representation of
      the [certificate]. *)
  val encode_der  : t -> Cstruct.t

  (** [decode_pem_multiple pem] is [t list], where all certificates of the [pem]
       are extracted *)
  val decode_pem_multiple : Cstruct.t -> (t list, [> R.msg ]) result

  (** [decode_pem pem] is [t], where the single certificate of the
      [pem] is extracted *)
  val decode_pem : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_pem_multiple certificates] is [pem], the pem encoded certificates. *)
  val encode_pem_multiple : t list -> Cstruct.t

  (** [encode_pem certificate] is [pem], the pem encoded certificate. *)
  val encode_pem : t -> Cstruct.t

  (** {1 Operations on certificates} *)

  (** The polymorphic variant of public key types. *)
  type key_type = [ `RSA | `EC of Asn.oid ]

  (** [supports_keytype certificate key_type] is [result], whether public key of
      the [certificate] matches the given [key_type]. *)
  val supports_keytype : t -> key_type -> bool

  (** [public_key certificate] is [pk], the public key of the [certificate]. *)
  val public_key : t -> Public_key.t

  (** [hostnames certficate] are [hostnames], the list of hostnames this
      [certificate] is valid for.  Currently, these are the DNS names of the
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}Subject Alternative Name}
      extension, if present, or otherwise the singleton list containing the common
      name. *)
  val hostnames : t -> Domain_name.Set.t

  (** The polymorphic variant for hostname validation. *)
  type host = [ `Strict | `Wildcard ] * [ `host ] Domain_name.t

  (** [supports_hostname certificate host] is [result], whether the [certificate]
      contains the given [host], using {!hostnames}. *)
  val supports_hostname : t -> host -> bool

  (** [fingerprint hash cert] is [digest], the digest of [cert] using the
      specified [hash] algorithm *)
  val fingerprint : Nocrypto.Hash.hash -> t -> Cstruct.t

  (** [subject certificate] is [dn], the subject as {{!distinguished_name}dn} of
      the [certificate]. *)
  val subject : t -> Distinguished_name.t

  (** [issuer certificate] is [dn], the issuer as {{!distinguished_name}dn} of
      the [certificate]. *)
  val issuer : t -> Distinguished_name.t

  (** [serial certificate] is [sn], the serial number of the [certificate]. *)
  val serial : t -> Z.t

  (** [validity certificate] is [from, until], the validity of the certificate. *)
  val validity : t -> Ptime.t * Ptime.t

  (** [extensions certificate] is the extension map of [certificate]. *)
  val extensions : t -> Extension.t
end

(** Certificate Signing request *)

(** A certificate authority (CA) deals with
    {{:https://tools.ietf.org/html/rfc2986}PKCS 10 certificate signing requests},
    their construction and encoding, and provisioning using a private key to
    generate a certificate with a signature thereof. *)
module Signing_request : sig
  (** The abstract type of a (self-signed) certification request. *)
  type t

  (** {1 Decoding and encoding in ASN.1 DER and PEM format} *)

  (** [decode_der cstruct] is [signing_request], the ASN.1 decoded
      [cstruct] or an error. *)
  val decode_der : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_der sr] is [cstruct], the ASN.1 encoded representation of the [sr]. *)
  val encode_der : t -> Cstruct.t

  (** [decode_pem pem] is [t], where the single signing request of the [pem] is extracted *)
  val decode_pem : Cstruct.t -> (t, [> R.msg ]) result

  (** [encode_pem signing_request] is [pem], the pem encoded signing request. *)
  val encode_pem : t -> Cstruct.t

  (** {1 Construction of a signing request} *)

  module Ext : sig
    (** The GADT of certificate request extensions, as defined in
        {{:http://tools.ietf.org/html/rfc2985}PKCS 9 (RFC 2985)}. *)
    type _ k =
      | Password : string k
      | Name : string k
      | Extensions : Extension.t k

    include Gmap.S with type 'a key = 'a k

    val pp : t Fmt.t
  end

  (** The raw request info of a
      {{:https://tools.ietf.org/html/rfc2986#section-4}PKCS 10 certification request info}. *)
  type request_info = {
    subject    : Distinguished_name.t ;
    public_key : Public_key.t ;
    extensions : Ext.t ;
  }

  (** [info signing_request] is {!request_info}, the information inside the
      {!signing_request}. *)
  val info : t -> request_info

  (** [create subject ~digest ~extensions private] creates [signing_request],
      a certification request using the given [subject], [digest] (defaults to
      [`SHA256]) and list of [extensions]. *)
  val create : Distinguished_name.t -> ?digest:Nocrypto.Hash.hash ->
    ?extensions:Ext.t -> Private_key.t -> t

  (** {1 Provision a signing request to a certificate} *)

  (** [sign signing_request ~digest ~valid_from ~valid_until ~serial ~extensions private issuer]
      creates [certificate], a signed certificate.  Public key and subject are
      taken from the [signing_request], the [extensions] are added to the X.509
      certificate.  The [private] key is used to sign the certificate, the
      [issuer] is recorded in the certificate.  The digest defaults to
      [`SHA256].  The [serial] defaults to a random value between 1 and 2^64.
      Certificate version is always 3.  Please note that the extensions in the
      [signing_request] are ignored, you can pass them using:

{[match Ext.find Extensions (info csr).extensions with
| Ok ext -> ext
| Error _ -> Extension.empty
]} *)
  val sign : t -> valid_from:Ptime.t -> valid_until:Ptime.t ->
    ?digest:Nocrypto.Hash.hash -> ?serial:Z.t ->
    ?extensions:Extension.t -> Private_key.t ->
    Distinguished_name.t -> Certificate.t
end

(** X.509 Certificate Revocation Lists. *)
module CRL : sig
  (** A certificate revocation list is a signed structure consisting of an
      issuer, a timestamp, possibly a timestamp when to expect the next update,
      and a list of revoked certificates (represented by a serial, a revocation
      date, and extensions (e.g. reason) - see
      {{:https://tools.ietf.org/html/rfc5280#section-5.2}RFC 5280 section 5.2}
      for a list of available extensions (not enforced)).  It also may contain
      any extensions, e.g. a CRL number and whether it is partial or complete. *)

  (** The type of a revocation list, kept abstract. *)
  type t

  (** {1 Encoding and decoding in ASN.1 DER format} *)

  (** [encode_der crl] is [buffer], the ASN.1 DER encoding of the given
      certificate revocation list. *)
  val encode_der : t -> Cstruct.t

  (** [decode_der buffer] is [crl], the certificate revocation list of the
      ASN.1 encoded buffer. *)
  val decode_der : Cstruct.t -> (t, [> R.msg ]) result

  (** {1 Operations on CRLs} *)

  (** [issuer c] is the issuer of the revocation list. *)
  val issuer : t -> Distinguished_name.t

  (** [this_update t] is the timestamp of the revocation list. *)
  val this_update : t -> Ptime.t

  (** [next_update t] is either [None] or [Some ts], the timestamp of the next
      update. *)
  val next_update : t -> Ptime.t option

  (** The type of a revoked certificate, which consists of a serial number, the
      revocation date, and possibly extensions.  See
      {{:https://tools.ietf.org/html/rfc5280#section-5.3}RFC 5280 section 5.3}
      for allowed extensions (not enforced). *)
  type revoked_cert = {
    serial : Z.t ;
    date : Ptime.t ;
    extensions : Extension.t
  }

  (** [reason revoked] extracts the [Reason] extension from [revoked] if
      present. *)
  val reason : revoked_cert -> Extension.reason option

  (** [revoked_certificates t] is the list of revoked certificates of the
      revocation list. *)
  val revoked_certificates : t -> revoked_cert list

  (** [extensions t] is the list of extensions, see RFC 5280 section 5.2 for
      possible values. *)
  val extensions : t -> Extension.t

  (** [crl_number t] is the number of the CRL. *)
  val crl_number : t -> int option

  (** {1 Validation and verification of CRLs} *)

  (** [validate t pk] validates the digital signature of the revocation list. *)
  val validate : t -> Public_key.t -> bool

  (** [verify t ~time cert] verifies that the issuer of [t] matches the subject
      of [cert], and validates the digital signature of the revocation list.  If
      [time] is provided, it must be after [this_update] and before
      [next_update] of [t]. *)
  val verify : t -> ?time:Ptime.t -> Certificate.t -> bool

  (** [is_revoked crls ~issuer ~cert] is [true] if there exists a revocation of
      [cert] in [crls] which is signed by the [issuer].  The subject of [issuer]
      must match the issuer of the crl. *)
  val is_revoked : t list -> issuer:Certificate.t -> cert:Certificate.t -> bool

  (** {1 Construction and signing of CRLs} *)

  (** [revoked ~digest ~issuer ~this_update ~next_update ~extensions certs priv]
      constructs a revocation list with the given parameters. *)
  val revoke : ?digest:Nocrypto.Hash.hash ->
    issuer:Distinguished_name.t ->
    this_update:Ptime.t -> ?next_update:Ptime.t ->
    ?extensions:Extension.t ->
    revoked_cert list -> Private_key.t -> t

  (** [revoke_certificate cert ~this_update ~next_update t priv] adds [cert] to
      the revocation list, increments its counter, adjusts [this_update] and
      [next_update] timestamps, and digitally signs it using [priv]. *)
  val revoke_certificate : revoked_cert ->
    this_update:Ptime.t -> ?next_update:Ptime.t -> t -> Private_key.t -> t

  (** [revoke_certificates certs ~this_update ~next_update t priv] adds [certs]
      to the revocation list, increments its counter, adjusts [this_update] and
      [next_update] timestamps, and digitally signs it using [priv]. *)
  val revoke_certificates : revoked_cert list ->
    this_update:Ptime.t -> ?next_update:Ptime.t -> t -> Private_key.t -> t
end

(** Chain Validation. *)
module Validation : sig
  (** A chain of pairwise signed X.509 certificates is sent to the endpoint,
      which use these to authenticate the other endpoint.  Usually a set of
      trust anchors is configured on the endpoint, and the chain needs to be
      rooted in one of the trust anchors.  In reality, chains may be incomplete
      or reversed, and there can be multiple paths from the leaf certificate to
      a trust anchor.

      RFC 5280 specifies a {{:https://tools.ietf.org/html/rfc5280#section-6}path
      validation} algorithm for authenticating chains, but this does not handle
      multiple possible paths.  {{:https://tools.ietf.org/html/rfc4158}RFC 4158}
      describes possible path building strategies.

      This module provides path building, chain of trust verification, trust
      anchor (certificate authority) validation, and validation via a
      fingerprint list (for a trust on first use implementation).
  *)


  (** {1 Certificate Authorities} *)

  (** The polymorphic variant of possible certificate authorities failures. *)
  type ca_error = [
    | `CAIssuerSubjectMismatch of Certificate.t
    | `CAInvalidVersion of Certificate.t
    | `CAInvalidSelfSignature of Certificate.t
    | `CACertificateExpired of Certificate.t * Ptime.t option
    | `CAInvalidExtensions of Certificate.t
  ]

  (** [pp_ca_error ppf ca_error] pretty-prints the CA error [ca_error]. *)
  val pp_ca_error : ca_error Fmt.t

  (** [valid_ca ~time certificate] is [result], which is [Ok ()] if the given
      certificate is self-signed, it is valid at [time], its extensions are not
      present (if X.509 version 1 certificate), or are appropriate for a CA
      (BasicConstraints is present and true, KeyUsage extension contains
      keyCertSign). *)
  val valid_ca : ?time:Ptime.t -> Certificate.t -> (unit, ca_error) result

  (** [valid_cas ~time certificates] is [valid_certificates], only those
      certificates which pass the {!valid_ca} check. *)
  val valid_cas : ?time:Ptime.t -> Certificate.t list -> Certificate.t list

  (** {1 Chain of trust verification} *)

  (** The polymorphic variant of a leaf certificate validation error. *)
  type leaf_validation_error = [
    | `LeafCertificateExpired of Certificate.t * Ptime.t option
    | `LeafInvalidName of Certificate.t * Certificate.host option
    | `LeafInvalidVersion of Certificate.t
    | `LeafInvalidExtensions of Certificate.t
  ]

  (** The polymorphic variant of a chain validation error. *)
  type chain_validation_error = [
    | `IntermediateInvalidExtensions of Certificate.t
    | `IntermediateCertificateExpired of Certificate.t * Ptime.t option
    | `IntermediateInvalidVersion of Certificate.t
    | `ChainIssuerSubjectMismatch of Certificate.t * Certificate.t
    | `ChainAuthorityKeyIdSubjectKeyIdMismatch of Certificate.t * Certificate.t
    | `ChainInvalidSignature of Certificate.t * Certificate.t
    | `ChainInvalidPathlen of Certificate.t * int
    | `EmptyCertificateChain
    | `NoTrustAnchor of Certificate.t
    | `Revoked of Certificate.t
  ]

  (** [build_paths server rest] is [paths], which are all possible certificate
      paths starting with [server].  These chains (C1..Cn) fulfill the predicate
      that each certificate Cn is issued by the next one in the chain (C(n+1)):
      the issuer of Cn matches the subject of C(n+1).  This is as described in
      {{:https://tools.ietf.org/html/rfc4158}RFC 4158}. *)
  val build_paths : Certificate.t -> Certificate.t list -> Certificate.t list list

  (** The polymorphic variant of a chain validation error: either the leaf
      certificate is problematic, or the chain itself. *)
  type chain_error = [
    | `Leaf of leaf_validation_error
    | `Chain of chain_validation_error
  ]

  (** [pp_chain_error ppf chain_error] pretty-prints the [chain_error]. *)
  val pp_chain_error : chain_error Fmt.t

  (** [verify_chain ~host ~time ~revoked ~anchors chain] is [result], either
      [Ok] and the trust anchor used to verify the chain, or [Error] and the
      chain error.  RFC 5280 describes the implemented
      {{:https://tools.ietf.org/html/rfc5280#section-6.1}path validation}
      algorithm: The validity period of the given certificates is checked
      against the [time].  The X509v3 extensions of the [chain] are checked,
      then a chain of trust from [anchors] to the server certificate is
      validated.  The path length constraints are checked.  The server
      certificate is checked to contain the given [host], using {!hostnames}.
      The returned certificate is the root of the chain, a member of the given
      list of [anchors]. *)
  val verify_chain : ?host:Certificate.host -> ?time:Ptime.t ->
    ?revoked:(issuer:Certificate.t -> cert:Certificate.t -> bool) ->
    anchors:(Certificate.t list) -> Certificate.t list ->
    (Certificate.t, chain_error) result

  (** The polymorphic variant of a fingerprint validation error. *)
  type fingerprint_validation_error = [
    | `ServerNameNotPresent of Certificate.t * [ `raw ] Domain_name.t
    | `NameNotInList of Certificate.t
    | `InvalidFingerprint of Certificate.t * Cstruct.t * Cstruct.t
  ]

  (** The polymorphic variant of validation errors. *)
  type validation_error = [
    | `EmptyCertificateChain
    | `InvalidChain
    | `Leaf of leaf_validation_error
    | `Fingerprint of fingerprint_validation_error
  ]

  (** [pp_validation_error ppf validation_error] pretty-prints the
      [validation_error]. *)
  val pp_validation_error : validation_error Fmt.t

  type r = ((Certificate.t list * Certificate.t) option, validation_error) result

  (** [verify_chain_of_trust ~host ~time ~revoked ~anchors certificates] is
      [result].  First, all possible paths are constructed using the
      {!build_paths} function, the first certificate of the chain is verified to
      be a valid leaf certificate (no BasicConstraints extension) and contains
      the given [host] (using {!hostnames}); if some path is valid, using
      {!verify_chain}, the result will be [Ok] and contain the actual
      certificate chain and the trust anchor. *)
  val verify_chain_of_trust :
    ?host:Certificate.host -> ?time:Ptime.t ->
    ?revoked:(issuer:Certificate.t -> cert:Certificate.t -> bool) ->
    anchors:(Certificate.t list) -> Certificate.t list -> r

  (** {1 Fingerprint verification} *)

  (** [trust_key_fingerprint ~time ~hash ~fingerprints certificates] is
      [result], the first element of [certificates] is verified against the
      given [fingerprints] map (hostname to public key fingerprint) using
      {!key_fingerprint}.  The certificate has to be valid in the given [time].
      If a [host] is provided, the certificate is checked for this name.  The
      [`Wildcard hostname] of the fingerprint list must match the name in the
      certificate, using {!hostnames}. *)
  val trust_key_fingerprint :
    ?host:Certificate.host -> ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:('a Domain_name.t * Cstruct.t) list -> Certificate.t list -> r

  (** [trust_cert_fingerprint ~time ~hash ~fingerprints certificates] is
      [result], the first element of [certificates] is verified to match the
      given [fingerprints] map (hostname to fingerprint) using {!fingerprint}.
      The certificate has to be valid in the given [time].  If a [host] is
      provided, the certificate is checked for this name.  The
      [`Wildcard hostname] of the fingerprint list must match the name in the
      certificate, using {!hostnames}. *)
  val trust_cert_fingerprint :
    ?host:Certificate.host -> ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:('a Domain_name.t * Cstruct.t) list -> Certificate.t list -> r
  [@@ocaml.deprecated "Pin public keys (use trust_key_fingerprint) instead of certificates."]
end

(** Certificate chain authenticators *)
module Authenticator : sig

  (** An authenticator [a] is a function type which takes a hostname and a
      certificate stack to an authentication decision {!Validation.r}. *)
  type t = ?host:Certificate.host -> Certificate.t list -> Validation.r

  (** [chain_of_trust ?time trust_anchors] is [authenticator], which uses the
      given [time] and list of [trust_anchors] to verify the certificate chain.
      This is an implementation of the algorithm described in
      {{:https://tools.ietf.org/html/rfc5280#section-6.1}RFC 5280}, using
      {!Validation.verify_chain_of_trust}.  The given trust anchors are not
      checked to be valid trust anchors any further (you have to do this
      manually with {!Validation.valid_ca} or {!Validation.valid_cas})!  *)
  val chain_of_trust : ?time:Ptime.t -> ?crls:CRL.t list ->
    Certificate.t list -> t

  (** [server_key_fingerprint ~time hash fingerprints] is an [authenticator]
      that uses the given [time] and list of [fingerprints] to verify that the
      fingerprint of the first element of the certificate chain matches the
      given fingerprint, using {!Validation.trust_key_fingerprint}. *)
  val server_key_fingerprint : ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:('a Domain_name.t * Cstruct.t) list -> t

  (** [server_cert_fingerprint ~time hash fingerprints] is an [authenticator]
      that uses the given [time] and list of [fingerprints] to verify the first
      element of the certificate chain, using
      {!Validation.trust_cert_fingerprint}. *)
  val server_cert_fingerprint : ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:('a Domain_name.t * Cstruct.t) list -> t
  [@@ocaml.deprecated "Pin public keys (use server_key_fingerprint) instead of certificates."]

  (** [null] is [authenticator], which always returns [Ok ()]. (Useful for
      testing purposes only.) *)
  val null : t
end
