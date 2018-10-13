/*******************************************************************************
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "eos_parse_eosio.h"
#include "eos_types.h"
#include "os.h"

void parseDelegateUndelegate(uint8_t *buffer, uint32_t bufferLength, uint8_t argNum, actionArgument_t *arg) {
    uint32_t read = 0;
    uint32_t written = 0;

    if (argNum == 0) {
        parseNameField(buffer, bufferLength, "From", arg, &read, &written);
    } else if (argNum == 1) {
        buffer += sizeof(name_t); bufferLength -= sizeof(name_t);
        parseNameField(buffer, bufferLength, "Receiver", arg, &read, &written);
    } else if (argNum == 2) {
        buffer += 2 * sizeof(name_t); bufferLength -= 2 * sizeof(name_t);
        parseAssetField(buffer, bufferLength, "NET", arg, &read, &written);
    } else if (argNum == 3) {
        buffer += 2 * sizeof(name_t) + sizeof(asset_t); bufferLength -= 2 * sizeof(name_t) + sizeof(asset_t);
        parseAssetField(buffer, bufferLength, "CPU", arg, &read, &written);
    }
}

void parseBuyRam(uint8_t *buffer, uint32_t bufferLength, uint8_t argNum, actionArgument_t *arg) {
    uint32_t read = 0;
    uint32_t written = 0;

    if (argNum == 0) {
        parseNameField(buffer, bufferLength, "Buyer", arg, &read, &written);
    } else if (argNum == 1) {
        buffer += sizeof(name_t); bufferLength -= sizeof(name_t);
        parseNameField(buffer, bufferLength, "Receiver", arg, &read, &written);
    } else if (argNum == 2) {
        buffer += 2 * sizeof(name_t); bufferLength -= 2 * sizeof(name_t);
        parseAssetField(buffer, bufferLength, "Tokens", arg, &read, &written);
    }
}

void parseBuyRamBytes(uint8_t *buffer, uint32_t bufferLength, uint8_t argNum, actionArgument_t *arg) {
    uint32_t read = 0;
    uint32_t written = 0;

    if (argNum == 0) {
        parseNameField(buffer, bufferLength, "Buyer", arg, &read, &written);
    } else if (argNum == 1) {
        buffer += sizeof(name_t); bufferLength -= sizeof(name_t);
        parseNameField(buffer, bufferLength, "Receiver", arg, &read, &written);
    } else if (argNum == 2) {
        buffer += 2 * sizeof(name_t); bufferLength -= 2 * sizeof(name_t);
        parseUint32Field(buffer, bufferLength, "Bytes", arg, &read, &written);
    }
}

void parseSellRam(uint8_t *buffer, uint32_t bufferLength, uint8_t argNum, actionArgument_t *arg) {
    uint32_t read = 0;
    uint32_t written = 0;

    if (argNum == 0) {
        parseNameField(buffer, bufferLength, "Receiver", arg, &read, &written);
    } else if (argNum == 1) {
        buffer += sizeof(name_t); bufferLength -= sizeof(name_t);
        parseUInt64Field(buffer, bufferLength, "Bytes", arg, &read, &written);
    }
}

void parseVoteProducer(uint8_t *buffer, uint32_t bufferLength, uint8_t argNum, actionArgument_t *arg) {
    uint32_t read = 0;
    uint32_t written = 0;

    if (argNum == 0) {
        parseNameField(buffer, bufferLength, "Account", arg, &read, &written);
        return;
    }

    uint8_t *proxyBuffer = buffer + sizeof(name_t);
    name_t proxy = 0;
    os_memmove(&proxy, proxyBuffer, sizeof(name_t));
    if (proxy != 0 && argNum == 1) {
        parseNameField(proxyBuffer, sizeof(name_t), "Proxy", arg, &read, &written);
        return;
    }

    // Move to producers list
    buffer += 2 * sizeof(name_t);
    bufferLength -= 2 * sizeof(name_t);

    uint32_t totalProducers = 0;
    read = unpack_variant32(buffer, bufferLength, &totalProducers);
    buffer += read; bufferLength -= read;

    uint32_t producerIndex = argNum - 1;
    buffer += producerIndex * sizeof(name_t);
    bufferLength -= producerIndex * sizeof(name_t);

    char label[14] = { 0 };
    snprintf(label, sizeof(label) - 1, "Producer #%d [%d]", argNum, totalProducers);
    parseNameField(buffer, bufferLength, label, arg, &read, &written);
}