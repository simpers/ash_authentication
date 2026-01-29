# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnKey do
  @moduledoc false

  @dsl [
    %Spark.Dsl.Section{
      name: :web_authn_key,
      describe: "Configure WebAuthn options for this resource",
      no_depend_modules: [:domain, :user_resource],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          doc: "The Ash domain to use to access this resource.",
          required: false
        ],
        user_resource: [
          type: {:behaviour, Ash.Resource},
          doc: "The user resource to which the key belong.",
          required: true
        ],
        credential_id_attribute_name: [
          type: :atom,
          doc: """
          The name of the attribute that stores the WebAuthn credential ID.

          ## What is a credential ID?

          When a user registers a WebAuthn credential (like a passkey or security key), 
          the authenticator generates a unique identifier for that specific credential. 
          Think of it as a serial number for the key on the user's device.

          This ID is sent by the browser during authentication so the server can look up 
          which credential (and therefore which user) is attempting to sign in. It is 
          unique per credential across all users and devices.

          ## Storage

          Stored as binary data (typically 16-64 bytes). This attribute will be marked 
          as `sensitive?: true` and will have a unique identity constraint.
          """,
          default: :credential_id
        ],
        public_key_attribute_name: [
          type: :atom,
          doc: """
          The name of the attribute that stores the public key for this credential.

          ## What is the public key?

          During WebAuthn registration, the authenticator generates a public-private key 
          pair. The private key never leaves the user's device (it's stored in the 
          hardware secure enclave, TPM, or browser's secure storage). The public key is 
          sent to the server and stored here.

          During authentication, the authenticator uses the private key to sign a 
          challenge. The server uses this stored public key to verify that signature, 
          proving the user possesses the authenticator without ever knowing the private key.

          ## Storage

          Stored as binary data in COSE (CBOR Object Signing and Encryption) format. 
          This is a standardized format that the WebAuthn library uses for signature 
          verification. This attribute will be marked as `sensitive?: true`.
          """,
          default: :public_key
        ],
        sign_count_attribute_name: [
          type: :atom,
          doc: """
          The name of the attribute that stores the signature counter for this credential.

          ## What is the sign count?

          WebAuthn authenticators maintain a counter that increments each time the 
          credential is used to sign something. The server stores the last seen counter 
          value here and verifies that each new authentication has a strictly greater 
          counter value.

          ## Why does this matter?

          This is a security feature to detect cloned credentials. If an attacker 
          somehow extracts a credential from a hardware key (which should be very 
          difficult), the cloned key and the original key would have the same counter. 
          When the clone is used, its counter would be lower than expected, revealing 
          that something is wrong.

          ## Storage

          Stored as an integer. Initialized to 0 when the credential is registered 
          and updated after each successful authentication.
          """,
          default: :sign_count
        ],
        aaguid_attribute_name: [
          type: :atom,
          doc: """
          The name of the optional attribute that stores the Authenticator Attestation 
          Globally Unique Identifier (AAGUID).

          ## What is an AAGUID?

          The AAGUID is a 128-bit identifier that indicates the type/model of the 
          authenticator (e.g., "this is a YubiKey 5", "this is an Apple Touch ID", 
          "this is a Google Titan key"). It is provided during registration if the 
          authenticator supports attestation.

          ## Why store it?

          While not strictly required for authentication, the AAGUID can be useful for:
          - Displaying the device type to users in a "manage my devices" UI
          - Enterprise policies that restrict which authenticator types are allowed
          - Debugging and support purposes
          - Audit logging

          ## Storage

          Stored as binary data (16 bytes). This is optional because not all 
          authenticators provide attestation data.
          """,
          default: :aaguid
        ],
        transports_attribute_name: [
          type: :atom,
          doc: """
          The name of the optional attribute that stores the transport methods 
          supported by this credential.

          ## What are transports?

          Transports indicate how the browser communicates with the authenticator:
          - `usb` - Physical USB connection (e.g., YubiKey inserted into port)
          - `nfc` - Near-field communication (tapping a key on a phone)
          - `ble` - Bluetooth Low Energy (wireless key)
          - `internal` - Built-in authenticator (e.g., Touch ID, Windows Hello)
          - `hybrid` - Hybrid transport methods

          ## Why store it?

          These are hints stored during registration that can help the browser 
          communicate with the authenticator more efficiently during subsequent 
          authentications. They are optional but recommended for the best user 
          experience, especially for cross-device authentication scenarios.

          ## Storage

          Typically stored as an array of strings or a serialized format. The exact 
          storage format depends on your WebAuthn library.
          """,
          default: :transports
        ],
        last_used_at_attribute_name: [
          type: :atom,
          doc: """
          The name of the optional attribute that stores when this credential was 
          last used for authentication.

          ## Why track this?

          Useful for:
          - Helping users identify stale or unused credentials in a device management UI
          - Security auditing and anomaly detection
          - Deciding when to prompt users to clean up old credentials
          - Detecting if a backup credential has been used (indicating the primary 
            device may have been lost)

          ## Storage

          Typically stored as a UTC datetime. This field is updated each time 
          the credential is used to successfully authenticate.
          """,
          default: :last_used_at
        ],
        user_id_attribute_name: [
          type: :atom,
          doc: "The name of the `user_id` attribute on this resource.",
          default: :user_id
        ],
        upsert_action_name: [
          type: :atom,
          doc: "The name of the action used to create and update records.",
          default: :upsert
        ],
        destroy_action_name: [
          type: :atom,
          doc: "The name of the action used to destroy records.",
          default: :destroy
        ],
        read_action_name: [
          type: :atom,
          doc: "The name of the action used to query keys.",
          default: :read
        ],
        user_relationship_name: [
          type: :atom,
          doc:
            "The name of the belongs-to relationship between a WebAuthn key and its related user.",
          default: :user
        ]
      ]
    }
  ]

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [
      AshAuthentication.WebAuthnKey.Transformer,
      AshAuthentication.WebAuthnKey.Verifier
    ]
end
