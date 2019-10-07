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

(* Escaping is described in RFC4514. Escaing '=' is optional, otherwise the
 * following is minimal, using the character instead of hex where possible. *)
let pp_attribute_value ?(osf = false) () ppf s =
  let n = String.length s in
  for i = 0 to n - 1 do
    match s.[i] with
    | '#' when i = 0 -> Fmt.string ppf "\\#"
    | ' ' when i = 0 || i = n - 1 -> Fmt.string ppf "\\ "
    | ',' when not osf -> Fmt.string ppf "\\,"
    | ';' when not osf -> Fmt.string ppf "\\;"
    | '/' when osf -> Fmt.string ppf "\\/"
    | '"' | '+' | '<' | '=' | '>' | '\\' as c -> Fmt.pf ppf "\\%c" c
    | '\x00' -> Fmt.string ppf "\\00"
    | c -> Fmt.char ppf c
  done

let pp_string_hex ppf s =
  for i = 0 to String.length s - 1 do
    Fmt.pf ppf "%02x" (Char.code s.[i])
  done

let pp_attribute ?osf () ppf attr =
  let pp_av = pp_attribute_value ?osf () in
  match attr with
  | CN s -> Fmt.pf ppf "CN=%a" pp_av s
  | Serialnumber s -> Fmt.pf ppf "Serialnumber=%a" pp_av s
  | C s -> Fmt.pf ppf "C=%a" pp_av s
  | L s -> Fmt.pf ppf "L=%a" pp_av s
  | SP s -> Fmt.pf ppf "SP=%a" pp_av s
  | O s -> Fmt.pf ppf "O=%a" pp_av s
  | OU s -> Fmt.pf ppf "OU=%a" pp_av s
  | T s -> Fmt.pf ppf "T=%a" pp_av s
  | DNQ s -> Fmt.pf ppf "DNQ=%a" pp_av s
  | Mail s -> Fmt.pf ppf "Mail=%a" pp_av s
  | DC s -> Fmt.pf ppf "DC=%a" pp_av s
  | Given_name s -> Fmt.pf ppf "Given_name=%a" pp_av s
  | Surname s -> Fmt.pf ppf "Surname=%a" pp_av s
  | Initials s -> Fmt.pf ppf "Initials=%a" pp_av s
  | Pseudonym s -> Fmt.pf ppf "Pseudonym=%a" pp_av s
  | Generation s -> Fmt.pf ppf "Generation=%a" pp_av s
  | Other (oid, s) -> Fmt.pf ppf "%a=#%a" Asn.OID.pp oid pp_string_hex s

module K = struct
  type t = attribute

  let compare t t' =
    match t, t' with
    | CN a, CN b -> String.compare a b
    | CN _, _ -> -1 | _, CN _ -> 1
    | Serialnumber a, Serialnumber b -> String.compare a b
    | Serialnumber _, _ -> -1 | _, Serialnumber _ -> 1
    | C a, C b -> String.compare a b
    | C _, _ -> -1 | _, C _ -> 1
    | L a, L b -> String.compare a b
    | L _, _ -> -1 | _, L _ -> 1
    | SP a, SP b -> String.compare a b
    | SP _, _ -> -1 | _, SP _ -> 1
    | O a, O b -> String.compare a b
    | O _, _ -> -1 | _, O _ -> 1
    | OU a, OU b -> String.compare a b
    | OU _, _ -> -1 | _, OU _ -> 1
    | T a, T b -> String.compare a b
    | T _, _ -> -1 | _, T _ -> 1
    | DNQ a, DNQ b -> String.compare a b
    | DNQ _, _ -> -1 | _, DNQ _ -> 1
    | Mail a, Mail b -> String.compare a b
    | Mail _, _ -> -1 | _, Mail _ -> 1
    | DC a, DC b -> String.compare a b
    | DC _, _ -> -1 | _, DC _ -> 1
    | Given_name a, Given_name b -> String.compare a b
    | Given_name _, _ -> -1 | _, Given_name _ -> 1
    | Surname a, Surname b -> String.compare a b
    | Surname _, _ -> -1 | _, Surname _ -> 1
    | Initials a, Initials b -> String.compare a b
    | Initials _, _ -> -1 | _, Initials _ -> 1
    | Pseudonym a, Pseudonym b -> String.compare a b
    | Pseudonym _, _ -> -1 | _, Pseudonym _ -> 1
    | Generation a, Generation b -> String.compare a b
    | Generation _, _ -> -1 | _, Generation _ -> 1
    | Other (oid_a, v_a), Other (oid_b, v_b) ->
      match Asn.OID.compare oid_a oid_b with
      | 0 -> String.compare v_a v_b
      | x when x < 0 -> -1
      | _ -> 1
end

module Relative_distinguished_name = Set.Make(K)

(* TODO:
   - each RDN should be a non-empty set
   - nothing prevents a user from putting Other (base 2 5 <| 4 <| 3, "foo")
     and Common_name "foo" into the same RDN -- which are identical (i.e. Other
     should filter the other named constructors) *)
type t = Relative_distinguished_name.t list

let equal a b =
  List.length a = List.length b &&
  List.for_all2 Relative_distinguished_name.equal a b

let make_pp ?(style = `RFC_comma) () ppf dn =
  let pp_a = pp_attribute ~osf:(style = `OSF) () in
  let pp_rdn ppf rdn =
    Fmt.(list ~sep:(unit "+") pp_a) ppf
      (Relative_distinguished_name.elements rdn)
  in
  match style with
  | `RFC_comma -> Fmt.(list ~sep:(unit "," ++ cut) pp_rdn) ppf (List.rev dn)
  | `RFC_comma_sp -> Fmt.(list ~sep:comma pp_rdn) ppf (List.rev dn)
  | `RFC_semi -> Fmt.(list ~sep:(unit ";" ++ cut) pp_rdn) ppf (List.rev dn)
  | `RFC_semi_sp -> Fmt.(list ~sep:semi pp_rdn) ppf (List.rev dn)
  | `OSF -> Fmt.(list (any "/" ++ pp_rdn)) ppf dn

let pp = Fmt.hbox (make_pp ())

module Asn = struct
  open Asn.S
  open Asn_grammars

  (* ASN `Name' fragmet appears all over. *)

  (* rfc5280 section 4.1.2.4 - name components we "must" handle. *)
  (* A list of abbreviations: http://pic.dhe.ibm.com/infocenter/wmqv7/v7r1/index.jsp?topic=%2Fcom.ibm.mq.doc%2Fsy10570_.htm *)
  (* Also rfc4519. *)

  (* See rfc5280 section 4.1.2.4. *)
  let directory_name =
    let f = function | `C1 s -> s | `C2 s -> s | `C3 s -> s
                     | `C4 s -> s | `C5 s -> s | `C6 s -> s
    and g s = `C1 s in
    map f g @@
    choice6
      utf8_string printable_string
      ia5_string universal_string teletex_string bmp_string


  (* We flatten the sequence-of-set-of-tuple here into a single list.
  * This means that we can't write non-singleton sets back.
  * Does anyone need that, ever?
  *)

  let name =
    let open Registry in

    let a_f = case_of_oid_f [
      (domain_component              , fun x -> DC x) ;
      (X520.common_name              , fun x -> CN x) ;
      (X520.serial_number            , fun x -> Serialnumber x) ;
      (X520.country_name             , fun x -> C x) ;
      (X520.locality_name            , fun x -> L x) ;
      (X520.state_or_province_name   , fun x -> SP x) ;
      (X520.organization_name        , fun x -> O x) ;
      (X520.organizational_unit_name , fun x -> OU x) ;
      (X520.title                    , fun x -> T x) ;
      (X520.dn_qualifier             , fun x -> DNQ x) ;
      (PKCS9.email                   , fun x -> Mail x) ;
      (X520.given_name               , fun x -> Given_name x) ;
      (X520.surname                  , fun x -> Surname x) ;
      (X520.initials                 , fun x -> Initials x) ;
      (X520.pseudonym                , fun x -> Pseudonym x) ;
      (X520.generation_qualifier     , fun x -> Generation x) ]
      ~default:(fun oid x -> Other (oid, x))

    and a_g = function
      | DC x -> (domain_component, x )
      | CN x -> (X520.common_name, x )
      | Serialnumber x -> (X520.serial_number, x )
      | C x -> (X520.country_name, x )
      | L x -> (X520.locality_name, x )
      | SP x -> (X520.state_or_province_name, x )
      | O x -> (X520.organization_name, x )
      | OU x -> (X520.organizational_unit_name, x )
      | T x -> (X520.title, x )
      | DNQ x -> (X520.dn_qualifier, x )
      | Mail x -> (PKCS9.email, x )
      | Given_name x -> (X520.given_name, x )
      | Surname x -> (X520.surname, x )
      | Initials x -> (X520.initials, x )
      | Pseudonym x -> (X520.pseudonym, x )
      | Generation x -> (X520.generation_qualifier, x )
      | Other (oid, x) -> (oid, x )
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" directory_name)
    in
    let rd_name =
      let f exts =
        List.fold_left
          (fun set attr -> Relative_distinguished_name.add attr set)
          Relative_distinguished_name.empty exts
      and g map = Relative_distinguished_name.elements map
      in
      map f g @@ set_of attribute_tv
    in
    sequence_of rd_name (* A vacuous choice, in the standard. *)

  let (name_of_cstruct, name_to_cstruct) =
    projections_of Asn.der name
end

let decode_der cs = Asn_grammars.err_to_msg (Asn.name_of_cstruct cs)

let encode_der = Asn.name_to_cstruct
