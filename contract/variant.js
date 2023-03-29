export async function handle(state, action) {
  const input = action.input;

  const signatures = state.signatures;
  let message_counter = state.message_counter;

  if (input.function === "createContainer") {
    try {
      const { caller_address, sig, type, label } = input;
      const callerMessage = btoa(state.messages.evm + state.message_counter);
      ContractAssert(
        caller_address && sig && type,
        "ERROR_MISSING_REQUIRED_ARGUMENTS"
      );

      const caller =
        type === "ar"
          ? await _ownerToAddress(caller_address)
          : await _moleculeAddr(caller_address, callerMessage, sig, type);
      ContractAssert(
        typeof label === "string" && label.trim().length,
        "ERROR_INVALID_CONTAINER_LABEL"
      );

      type === "ar"
        ? await _verifyArSignature(caller_address, sig, state.messages.ar)
        : await _moleculeSignatureVerification(
            caller_address,
            callerMessage,
            sig,
            type
          );

      const timestamp = EXM.getDate().getTime();

      state.containers.push({
        id: SmartWeave.transaction.id,
        label: label.trim(),
        controller_address: caller,
        network: type,
        first_linkage: timestamp,
        last_modification: timestamp,
        addresses: [{ address: caller, network: type, proof: sig }],
        vouched_by: [],
      });

      return { state };
    } catch (error) {
      throw new ContractError("error");
    }
  }

  if (input.function === "attestIdentity") {
    const {
      container_id,
      caller_address,
      new_addr,
      caller_proof,
      attestation_proof,
      caller_type,
      attest_type,
    } = input;

    const containerIndex = _getContainerIndex(container_id);
    const callerMessage = btoa(state.messages.evm + state.message_counter);
    const caller =
      caller_type === "ar"
        ? await _ownerToAddress(caller_address)
        : await _moleculeAddr(
            caller_address,
            callerMessage,
            caller_proof,
            caller_type
          );

    const new_address =
      attest_type === "ar"
        ? await _ownerToAddress(new_addr)
        : await _moleculeAddr(
            new_addr,
            callerMessage,
            attestation_proof,
            attest_type
          );
    const container = state.containers[containerIndex];

    ContractAssert(
      !container.addresses.map((addr) => addr.address).includes(new_address),
      "ERROR_ADDRESS_ADDED"
    );
    ContractAssert(new_address !== caller, "ERROR_INVALID_ATTESTATION");

    // 1- verify the caller is the container's controller
    ContractAssert(
      caller === container.controller_address,
      "ERROR_INVALID_CALLER"
    );

    caller_type === "ar"
      ? await _verifyArSignature(
          caller_address,
          caller_proof,
          state.messages.ar
        )
      : await _moleculeSignatureVerification(
          caller_address, // is the public key
          callerMessage,
          caller_proof,
          caller_type
        );
    // 2- verify that new_address attested the container controller

    attest_type === "ar"
      ? await _verifyArSignature(
          new_addr,
          attestation_proof,
          `ark+${container.controller_address}`
        )
      : await _moleculeSignatureVerification(
          new_addr,
          btoa(`ark+${container.controller_address}`),
          attestation_proof,
          attest_type
        );

    // 3- update the state

    state.containers[containerIndex].addresses.push({
      address: new_address,
      network: attest_type,
      proof: attestation_proof,
    });

    return { state };
  }

  if (input.function === "removeIdentity") {
    const { container_id, caller_address, identity_address, sig, type } = input;

    const callerMessage = btoa(state.messages.evm + state.message_counter);

    const caller =
      type === "ar"
        ? await _ownerToAddress(caller_address)
        : await _moleculeAddr(caller_address, callerMessage, sig, type);

    const containerIndex = _getContainerIndex(container_id);

    ContractAssert(
      caller === state.containers[containerIndex].controller_address,
      "ERROR_INVALID_CALLER"
    );

    const identityAddrIndex = state.containers[
      containerIndex
    ].addresses.findIndex((id) => id.address === identity_address);
    ContractAssert(identityAddrIndex >= 0, "ERROR_IDENTITY_ADDRESS_NOT_FOUND");

    type === "ar"
      ? await _verifyArSignature(caller_address, sig, state.messages.ar)
      : await _moleculeSignatureVerification(
          caller_address,
          callerMessage,
          sig,
          type
        );

    // if the container controller is removing with a single identity or the controller address itself, delete the container
    if (
      state.containers[containerIndex].addresses.length === 1 ||
      state.containers[containerIndex].controller_address === identity_address
    ) {
      state.containers.splice(containerIndex, 1);
      return { state };
    }

    state.containers[containerIndex].addresses.splice(identityAddrIndex, 1);

    return { state };
  }

  if (input.function === "editContainerLabel") {
    const { container_id, caller_address, sig, label, type } = input;

    const callerMessage = btoa(state.messages.evm + state.message_counter);

    const caller =
      type === "ar"
        ? await _ownerToAddress(caller_address)
        : await _moleculeAddr(caller_address, callerMessage, sig, type);

    const containerIndex = _getContainerIndex(container_id);
    ContractAssert(
      typeof label === "string" && label.trim().length,
      "ERROR_INVALID_CONTAINER_LABEL"
    );

    ContractAssert(
      caller === state.containers[containerIndex].controller_address,
      "ERROR_INVALID_CALLER"
    );

    type === "ar"
      ? await _verifyArSignature(caller_address, sig, state.messages.ar)
      : await _moleculeSignatureVerification(
          caller_address,
          callerMessage,
          sig,
          type
        );

    ContractAssert(
      state.containers[containerIndex].label !== label.trim(),
      "ERROR_LABEL_NOT_UPDATED"
    );
    state.containers[containerIndex].label = label.trim();

    return { state };
  }

  if (input.function === "deleteContainer") {
    const { container_id, caller_address, sig, type } = input;

    const callerMessage = btoa(state.messages.evm + state.message_counter);

    const caller =
      type === "ar"
        ? await _ownerToAddress(caller_address)
        : await _moleculeAddr(caller_address, callerMessage, sig, type);

    const containerIndex = _getContainerIndex(container_id);

    ContractAssert(
      caller === state.containers[containerIndex].controller_address,
      "ERROR_INVALID_CALLER"
    );

    type === "ar"
      ? await _verifyArSignature(caller_address, sig, state.messages.ar)
      : await _moleculeSignatureVerification(
          caller_address,
          callerMessage,
          sig,
          type
        );

    state.containers.splice(containerIndex, 1);

    return { state };
  }

  if (input.function === "vouchContainer") {
    const {
      caller_container_id,
      caller_address,
      sig,
      type,
      target_container_id,
    } = input;

    ContractAssert(
      caller_container_id !== target_container_id,
      "ERROR_CANNOT_SELF_VOUCH"
    );

    const callerMessage = btoa(state.messages.evm + state.message_counter);

    const caller =
      type === "ar"
        ? await _ownerToAddress(caller_address)
        : await _moleculeAddr(caller_address, callerMessage, sig, type);

    const callerContainerIndex = _getContainerIndex(caller_container_id);
    const targetContainerIndex = _getContainerIndex(target_container_id);
    const callerContainer = state.containers[callerContainerIndex];
    const targetContainer = state.containers[targetContainerIndex];
    const callerIdentities = callerContainer.addresses.map((id) => id.address);
    const targetIdentities = targetContainer.addresses.map((id) => id.address);

    ContractAssert(
      caller === callerContainer.controller_address,
      "ERROR_INVALID_CALLER"
    );

    for (const address of callerIdentities) {
      ContractAssert(
        !targetIdentities.includes(address),
        "ERROR_CANNOT_SELF_VOUCH"
      );
    }

    type === "ar"
      ? await _verifyArSignature(caller_address, sig, state.messages.ar)
      : await _moleculeSignatureVerification(
          caller_address,
          callerMessage,
          sig,
          type
        );

    state.containers[targetContainerIndex].vouched_by.push(caller_container_id);

    return { state };
  }

  // ADMIN FUNCTION

  if (input.function === "modifyMolecules") {
    const { jwk_n, sig, type, endpoint } = input;
    await _verifyArSignature(jwk_n, sig, state.messages.ar);
    const caller = await _ownerToAddress(jwk_n);
    ContractAssert(caller === state.admin, "ERROR_INVALID_CALLER");
    ContractAssert(
      typeof endpoint === "string" &&
        typeof type === "string" &&
        endpoint.length &&
        type.length,
      "ERROR_INVALID_ARGUMENT"
    );
    ContractAssert(
      endpoint.trim().length === endpoint.length &&
        type.trim().length === type.length,
      "ERROR_INVALID_ARGUMENT"
    );
    state.molecule_endpoints[type] = endpoint;

    return { state };
  }

  async function _moleculeAddr(caller, message, signature, type) {
    try {
      const moleculeEndpoint = await _typeToMolecule(type);
      const isValid = await EXM.deterministicFetch(
        `${moleculeEndpoint}/${caller}/${message}/${signature}`
      );

      if (isValid.asJSON()?.address) {
        return isValid.asJSON()?.address;
      }
      return caller;
    } catch (error) {
      throw new ContractError("ERROR_MOLECULE_CONNECTION");
    }
  }

  function _getContainerIndex(id) {
    const index = state.containers.findIndex(
      (container) => container.id === id
    );
    ContractAssert(index >= 0, "ERROR_INVALID_CONTAINER_ID");
    return index;
  }

  async function _ownerToAddress(pubkey) {
    try {
      const req = await EXM.deterministicFetch(
        `${state.molecule_endpoints.ar}/${pubkey}`
      );
      const address = req.asJSON()?.address;
      _validateArweaveAddress(address);
      return address;
    } catch (error) {
      throw new ContractError("ERROR_MOLECULE_SERVER_ERROR");
    }
  }

  async function _typeToMolecule(type) {
    ContractAssert(type in state.molecule_endpoints, "ERROR_TYPE_NOT_FOUND");
    return state.molecule_endpoints[type];
  }

  async function _getStateAddresses() {
    return state.containers
      .map((container) => container.addresses)
      .flat()
      .map((obj) => obj.address);
  }

  async function _moleculeSignatureVerification(
    caller,
    message,
    signature,
    type
  ) {
    try {
      ContractAssert(!signatures.includes(signature));
      const moleculeEndpoint = await _typeToMolecule(type);
      const isValid = await EXM.deterministicFetch(
        `${moleculeEndpoint}/${caller}/${message}/${signature}`
      );
      ContractAssert(isValid.asJSON()?.result, "ERROR_INVALID_CALLER");
      signatures.push(signature);
      state.message_counter += 1;
    } catch (error) {
      throw new ContractError("ERROR_MOLECULE_CONNECTION");
    }
  }

  async function _verifyArSignature(owner, signature, message) {
    try {
      _validatePubKeySyntax(owner);

      const encodedMessage = new TextEncoder().encode(message);
      const typedArraySig = Uint8Array.from(atob(signature), (c) =>
        c.charCodeAt(0)
      );
      const isValid = await SmartWeave.arweave.crypto.verify(
        owner,
        encodedMessage,
        typedArraySig
      );

      ContractAssert(isValid, "ERROR_INVALID_CALLER_SIGNATURE");
      ContractAssert(
        !state.signatures.includes(signature),
        "ERROR_SIGNATURE_ALREADY_USED"
      );
      state.signatures.push(signature);
    } catch (error) {
      throw new ContractError("ERROR_INVALID_CALLER_SIGNATURE");
    }
  }

  function _validateArweaveAddress(address) {
    ContractAssert(
      /[a-z0-9_-]{43}/i.test(address),
      "ERROR_INVALID_ARWEAVE_ADDRESS"
    );
  }

  function _validatePubKeySyntax(jwk_n) {
    ContractAssert(
      typeof jwk_n === "string" && jwk_n?.length === 683,
      "ERROR_INVALID_JWK_N_SYNTAX"
    );
  }
}
