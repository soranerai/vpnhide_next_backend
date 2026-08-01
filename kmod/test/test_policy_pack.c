#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#define main vpnhide_ctl_program_main
#include "../vpnhide_ctl.c"
#undef main

#define TEST_UID_COUNT 4096U
#define TEST_RULES_PER_UID 17U

int main(void)
{
	struct vpnhide_uid_vector kmod = {0}, lsposed = {0};
	struct vpnhide_port_policy ports = {0};
	struct app_hook_mask_vector masks = {0};
	struct vpnhide_iface_ioctl_data ifaces = {0};
	struct vpnhide_policy_payload_v3 *payload;
	struct vpnhide_port_target_v3 *packed_targets;
	struct vpnhide_port_rule_v3 *packed_rules;
	struct vpnhide_port_rule *rules;
	void *blob = NULL;
	uint32_t blob_size = 0;
	size_t total_rules = TEST_UID_COUNT * TEST_RULES_PER_UID;

	assert(sizeof(uid_t) == sizeof(__u32));
	kmod.items = calloc(TEST_UID_COUNT, sizeof(*kmod.items));
	lsposed.items = calloc(TEST_UID_COUNT, sizeof(*lsposed.items));
	ports.targets = calloc(TEST_UID_COUNT, sizeof(*ports.targets));
	masks.items = calloc(TEST_UID_COUNT, sizeof(*masks.items));
	rules = calloc(total_rules, sizeof(*rules));
	assert(kmod.items && lsposed.items && ports.targets && masks.items && rules);

	kmod.count = lsposed.count = ports.count = masks.count = TEST_UID_COUNT;
	for (size_t i = 0; i < TEST_UID_COUNT; i++) {
		uid_t uid = (uid_t)(10000U + i);
		kmod.items[i] = lsposed.items[i] = uid;
		ports.targets[i].uid = uid;
		ports.targets[i].mode = VH_PORT_POLICY_RULES;
		ports.targets[i].rule_count = TEST_RULES_PER_UID;
		ports.targets[i].rules = &rules[i * TEST_RULES_PER_UID];
		masks.items[i].uid = uid;
		masks.items[i].kernel_mask = (unsigned int)i;
		masks.items[i].has_kernel_override = 1;
		for (size_t j = 0; j < TEST_RULES_PER_UID; j++) {
			ports.targets[i].rules[j].start_port = (uint16_t)j;
			ports.targets[i].rules[j].end_port = (uint16_t)j;
			ports.targets[i].rules[j].protocol = VH_PROTO_TCP;
		}
	}

	assert(pack_policy_v3(&kmod, &lsposed, &ports, &masks, &ifaces,
			      0x1234U, 0x5678U, 1, &blob, &blob_size) == 0);
	payload = blob;
	assert(payload->total_size == blob_size);
	assert(payload->kmod_uids.count == TEST_UID_COUNT);
	assert(payload->lsposed_uids.count == TEST_UID_COUNT);
	assert(payload->port_targets.count == TEST_UID_COUNT);
	assert(payload->port_rules.count == total_rules);
	assert(payload->app_hook_masks.count == TEST_UID_COUNT);
	assert((size_t)payload->app_hook_masks.offset +
	       TEST_UID_COUNT * sizeof(struct vpnhide_app_hook_mask_v3) == blob_size);
	assert(((__u32 *)((unsigned char *)blob + payload->kmod_uids.offset))[4095] ==
	       14095U);
	packed_targets = (void *)((unsigned char *)blob +
				  payload->port_targets.offset);
	packed_rules = (void *)((unsigned char *)blob + payload->port_rules.offset);
	assert(packed_targets[4095].uid == 14095U);
	assert(packed_targets[4095].first_rule ==
	       (TEST_UID_COUNT - 1U) * TEST_RULES_PER_UID);
	assert(packed_targets[4095].rule_count == TEST_RULES_PER_UID);
	assert(packed_rules[total_rules - 1U].start_port ==
	       TEST_RULES_PER_UID - 1U);

	free(blob);
	free(rules);
	free(masks.items);
	free(ports.targets);
	free(lsposed.items);
	free(kmod.items);
	return 0;
}
