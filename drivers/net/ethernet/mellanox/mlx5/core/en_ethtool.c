/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "en.h"

static void mlx5e_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	strlcpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRIVER_VERSION " (" DRIVER_RELDATE ")",
		sizeof(drvinfo->version));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%d.%d.%d",
		 fw_rev_maj(mdev), fw_rev_min(mdev), fw_rev_sub(mdev));
	strlcpy(drvinfo->bus_info, pci_name(mdev->pdev),
		sizeof(drvinfo->bus_info));
}

struct ptys2ethtool_config {
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertised);
	u32 speed;
};

static struct ptys2ethtool_config ptys2ethtool_table[MLX5E_LINK_MODES_NUMBER];

#define MLX5_BUILD_PTYS2ETHTOOL_CONFIG(reg_, speed_, ...)               \
	({                                                              \
		struct ptys2ethtool_config *cfg;                        \
		const unsigned int modes[] = { __VA_ARGS__ };           \
		unsigned int i;                                         \
		cfg = &ptys2ethtool_table[reg_];                        \
		cfg->speed = speed_;                                    \
		bitmap_zero(cfg->supported,                             \
			    __ETHTOOL_LINK_MODE_MASK_NBITS);            \
		bitmap_zero(cfg->advertised,                            \
			    __ETHTOOL_LINK_MODE_MASK_NBITS);            \
		for (i = 0 ; i < ARRAY_SIZE(modes) ; ++i) {             \
			__set_bit(modes[i], cfg->supported);            \
			__set_bit(modes[i], cfg->advertised);           \
		}                                                       \
	})

void mlx5e_build_ptys2ethtool_map(void)
{
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_1000BASE_CX_SGMII, SPEED_1000,
				       ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_1000BASE_KX, SPEED_1000,
				       ETHTOOL_LINK_MODE_1000baseKX_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_CX4, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_KX4, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_KR, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_20GBASE_KR2, SPEED_20000,
				       ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_40GBASE_CR4, SPEED_40000,
				       ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_40GBASE_KR4, SPEED_40000,
				       ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_56GBASE_R4, SPEED_56000,
				       ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_CR, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_SR, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_ER, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_40GBASE_SR4, SPEED_40000,
				       ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_40GBASE_LR4, SPEED_40000,
				       ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_50GBASE_SR2, SPEED_50000,
				       ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_100GBASE_CR4, SPEED_100000,
				       ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_100GBASE_SR4, SPEED_100000,
				       ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_100GBASE_KR4, SPEED_100000,
				       ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_100GBASE_LR4, SPEED_100000,
				       ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_10GBASE_T, SPEED_10000,
				       ETHTOOL_LINK_MODE_10000baseT_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_25GBASE_CR, SPEED_25000,
				       ETHTOOL_LINK_MODE_25000baseCR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_25GBASE_KR, SPEED_25000,
				       ETHTOOL_LINK_MODE_25000baseKR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_25GBASE_SR, SPEED_25000,
				       ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_50GBASE_CR2, SPEED_50000,
				       ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT);
	MLX5_BUILD_PTYS2ETHTOOL_CONFIG(MLX5E_50GBASE_KR2, SPEED_50000,
				       ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT);
}

static int mlx5e_get_sset_count(struct net_device *dev, int sset)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return NUM_VPORT_COUNTERS + NUM_PPORT_COUNTERS +
		       priv->params.num_channels * NUM_RQ_STATS +
		       priv->params.num_channels * priv->params.num_tc *
						   NUM_SQ_STATS;
	/* fallthrough */
	default:
		return -EOPNOTSUPP;
	}
}

static void mlx5e_get_strings(struct net_device *dev,
			      uint32_t stringset, uint8_t *data)
{
	int i, j, tc, idx = 0;
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (stringset) {
	case ETH_SS_PRIV_FLAGS:
		break;

	case ETH_SS_TEST:
		break;

	case ETH_SS_STATS:
		/* VPORT counters */
		for (i = 0; i < NUM_VPORT_COUNTERS; i++)
			strcpy(data + (idx++) * ETH_GSTRING_LEN,
			       vport_strings[i]);

		/* PPORT counters */
		for (i = 0; i < NUM_PPORT_COUNTERS; i++)
			strcpy(data + (idx++) * ETH_GSTRING_LEN,
			       pport_strings[i]);

		/* per channel counters */
		for (i = 0; i < priv->params.num_channels; i++)
			for (j = 0; j < NUM_RQ_STATS; j++)
				sprintf(data + (idx++) * ETH_GSTRING_LEN,
					"rx%d_%s", i, rq_stats_strings[j]);

		for (i = 0; i < priv->params.num_channels; i++)
			for (tc = 0; tc < priv->params.num_tc; tc++)
				for (j = 0; j < NUM_SQ_STATS; j++)
					sprintf(data +
						(idx++) * ETH_GSTRING_LEN,
						"tx%d_%d_%s", i, tc,
						sq_stats_strings[j]);
		break;
	}
}

static void mlx5e_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i, j, tc, idx = 0;

	if (!data)
		return;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_update_stats(priv);
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < NUM_VPORT_COUNTERS; i++)
		data[idx++] = ((u64 *)&priv->stats.vport)[i];

	for (i = 0; i < NUM_PPORT_COUNTERS; i++)
		data[idx++] = be64_to_cpu(((__be64 *)&priv->stats.pport)[i]);

	/* per channel counters */
	for (i = 0; i < priv->params.num_channels; i++)
		for (j = 0; j < NUM_RQ_STATS; j++)
			data[idx++] = !test_bit(MLX5E_STATE_OPENED,
						&priv->state) ? 0 :
				       ((u64 *)&priv->channel[i]->rq.stats)[j];

	for (i = 0; i < priv->params.num_channels; i++)
		for (tc = 0; tc < priv->params.num_tc; tc++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				data[idx++] = !test_bit(MLX5E_STATE_OPENED,
							&priv->state) ? 0 :
				((u64 *)&priv->channel[i]->sq[tc].stats)[j];
}

static void mlx5e_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	param->rx_max_pending = 1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE;
	param->tx_max_pending = 1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE;
	param->rx_pending     = 1 << priv->params.log_rq_size;
	param->tx_pending     = 1 << priv->params.log_sq_size;
}

static int mlx5e_set_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	bool was_opened;
	u16 min_rx_wqes;
	u8 log_rq_size;
	u8 log_sq_size;
	int err = 0;

	if (param->rx_jumbo_pending) {
		netdev_info(dev, "%s: rx_jumbo_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_mini_pending) {
		netdev_info(dev, "%s: rx_mini_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_pending < (1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE)) {
		netdev_info(dev, "%s: rx_pending (%d) < min (%d)\n",
			    __func__, param->rx_pending,
			    1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE);
		return -EINVAL;
	}
	if (param->rx_pending > (1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE)) {
		netdev_info(dev, "%s: rx_pending (%d) > max (%d)\n",
			    __func__, param->rx_pending,
			    1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE);
		return -EINVAL;
	}
	if (param->tx_pending < (1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) < min (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}
	if (param->tx_pending > (1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) > max (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}

	log_rq_size = order_base_2(param->rx_pending);
	log_sq_size = order_base_2(param->tx_pending);
	min_rx_wqes = min_t(u16, param->rx_pending - 1,
			    MLX5E_PARAMS_DEFAULT_MIN_RX_WQES);

	if (log_rq_size == priv->params.log_rq_size &&
	    log_sq_size == priv->params.log_sq_size &&
	    min_rx_wqes == priv->params.min_rx_wqes)
		return 0;

	mutex_lock(&priv->state_lock);

	was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);
	if (was_opened)
		mlx5e_close_locked(dev);

	priv->params.log_rq_size = log_rq_size;
	priv->params.log_sq_size = log_sq_size;
	priv->params.min_rx_wqes = min_rx_wqes;

	if (was_opened)
		err = mlx5e_open_locked(dev);

	mutex_unlock(&priv->state_lock);

	return err;
}

static void mlx5e_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	ch->max_combined   = mlx5e_get_max_num_channels(priv->mdev);
	ch->combined_count = priv->params.num_channels;
}

static int mlx5e_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int ncv = mlx5e_get_max_num_channels(priv->mdev);
	unsigned int count = ch->combined_count;
	bool was_opened;
	int err = 0;

	if (!count) {
		netdev_info(dev, "%s: combined_count=0 not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (ch->rx_count || ch->tx_count) {
		netdev_info(dev, "%s: separate rx/tx count not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (count > ncv) {
		netdev_info(dev, "%s: count (%d) > max (%d)\n",
			    __func__, count, ncv);
		return -EINVAL;
	}

	if (priv->params.num_channels == count)
		return 0;

	mutex_lock(&priv->state_lock);

	was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);
	if (was_opened)
		mlx5e_close_locked(dev);

	priv->params.num_channels = count;

	if (was_opened)
		err = mlx5e_open_locked(dev);

	mutex_unlock(&priv->state_lock);

	return err;
}

static int mlx5e_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (!MLX5_CAP_GEN(priv->mdev, cq_moderation))
		return -ENOTSUPP;

	coal->rx_coalesce_usecs       = priv->params.rx_cq_moderation_usec;
	coal->rx_max_coalesced_frames = priv->params.rx_cq_moderation_pkts;
	coal->tx_coalesce_usecs       = priv->params.tx_cq_moderation_usec;
	coal->tx_max_coalesced_frames = priv->params.tx_cq_moderation_pkts;

	return 0;
}

static int mlx5e_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_channel *c;
	int tc;
	int i;

	if (!MLX5_CAP_GEN(mdev, cq_moderation))
		return -ENOTSUPP;

	mutex_lock(&priv->state_lock);
	priv->params.tx_cq_moderation_usec = coal->tx_coalesce_usecs;
	priv->params.tx_cq_moderation_pkts = coal->tx_max_coalesced_frames;
	priv->params.rx_cq_moderation_usec = coal->rx_coalesce_usecs;
	priv->params.rx_cq_moderation_pkts = coal->rx_max_coalesced_frames;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
		goto out;

	for (i = 0; i < priv->params.num_channels; ++i) {
		c = priv->channel[i];

		for (tc = 0; tc < c->num_tc; tc++) {
			mlx5_core_modify_cq_moderation(mdev,
						&c->sq[tc].cq.mcq,
						coal->tx_coalesce_usecs,
						coal->tx_max_coalesced_frames);
		}

		mlx5_core_modify_cq_moderation(mdev, &c->rq.cq.mcq,
					       coal->rx_coalesce_usecs,
					       coal->rx_max_coalesced_frames);
	}

out:
	mutex_unlock(&priv->state_lock);
	return 0;
}

static void ptys2ethtool_supported_link(unsigned long *supported_modes,
					u32 eth_proto_cap)
{
	int proto;

	for_each_set_bit(proto, (unsigned long *)&eth_proto_cap, MLX5E_LINK_MODES_NUMBER)
		bitmap_or(supported_modes, supported_modes,
			  ptys2ethtool_table[proto].supported,
			  __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static void ptys2ethtool_adver_link(unsigned long *advertising_modes,
				    u32 eth_proto_cap)
{
	int proto;

	for_each_set_bit(proto, (unsigned long *)&eth_proto_cap, MLX5E_LINK_MODES_NUMBER)
		bitmap_or(advertising_modes, advertising_modes,
			  ptys2ethtool_table[proto].advertised,
			  __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static void ptys2ethtool_supported_port(struct ethtool_link_ksettings *link_ksettings,
					u32 eth_proto_cap)
{
	if (eth_proto_cap & (MLX5E_PROT_MASK(MLX5E_10GBASE_CR)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_SR)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_CR4)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_SR4)
			   | MLX5E_PROT_MASK(MLX5E_100GBASE_SR4)
			   | MLX5E_PROT_MASK(MLX5E_1000BASE_CX_SGMII))) {
		ethtool_link_ksettings_add_link_mode(link_ksettings, supported, FIBRE);
	}

	if (eth_proto_cap & (MLX5E_PROT_MASK(MLX5E_100GBASE_KR4)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_KR4)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_KR)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_KX4)
			   | MLX5E_PROT_MASK(MLX5E_1000BASE_KX))) {
		ethtool_link_ksettings_add_link_mode(link_ksettings, supported, Backplane);
	}
}

static void get_speed_duplex(struct net_device *netdev,
			     u32 eth_proto_oper,
			     struct ethtool_link_ksettings *link_ksettings)
{
	int i;
	u32 speed = SPEED_UNKNOWN;
	u8 duplex = DUPLEX_UNKNOWN;

	if (!netif_carrier_ok(netdev))
		goto out;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_oper & MLX5E_PROT_MASK(i)) {
			speed = ptys2ethtool_table[i].speed;
			duplex = DUPLEX_FULL;
			break;
		}
	}
out:
	link_ksettings->base.speed = speed;
	link_ksettings->base.duplex = duplex;
}

static void get_supported(u32 eth_proto_cap,
			  struct ethtool_link_ksettings *link_ksettings)
{
	unsigned long *supported = link_ksettings->link_modes.supported;

	ptys2ethtool_supported_port(link_ksettings, eth_proto_cap);
	ptys2ethtool_supported_link(supported, eth_proto_cap);
	ethtool_link_ksettings_add_link_mode(link_ksettings, supported, Pause);
	ethtool_link_ksettings_add_link_mode(link_ksettings, supported, Asym_Pause);
}

static void get_advertising(u32 eth_proto_cap, u8 tx_pause,
			    u8 rx_pause,
			    struct ethtool_link_ksettings *link_ksettings)
{
	unsigned long *advertising = link_ksettings->link_modes.advertising;

	ptys2ethtool_adver_link(advertising, eth_proto_cap);
	if (tx_pause)
		ethtool_link_ksettings_add_link_mode(link_ksettings, advertising, Pause);
	if (tx_pause ^ rx_pause)
		ethtool_link_ksettings_add_link_mode(link_ksettings, advertising, Asym_Pause);
}

static u8 get_connector_port(u32 eth_proto)
{
	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_10GBASE_SR)
			 | MLX5E_PROT_MASK(MLX5E_40GBASE_SR4)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_SR4)
			 | MLX5E_PROT_MASK(MLX5E_1000BASE_CX_SGMII))) {
			return PORT_FIBRE;
	}

	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_40GBASE_CR4)
			 | MLX5E_PROT_MASK(MLX5E_10GBASE_CR)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_CR4))) {
			return PORT_DA;
	}

	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_10GBASE_KX4)
			 | MLX5E_PROT_MASK(MLX5E_10GBASE_KR)
			 | MLX5E_PROT_MASK(MLX5E_40GBASE_KR4)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_KR4))) {
			return PORT_NONE;
	}

	return PORT_OTHER;
}

static void get_lp_advertising(u32 eth_proto_lp,
			       struct ethtool_link_ksettings *link_ksettings)
{
	unsigned long *lp_advertising = link_ksettings->link_modes.lp_advertising;

	ptys2ethtool_adver_link(lp_advertising, eth_proto_lp);
}

static int mlx5e_get_link_ksettings(struct net_device *netdev,
				    struct ethtool_link_ksettings *link_ksettings)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_cap;
	u32 eth_proto_admin;
	u32 eth_proto_lp;
	u32 eth_proto_oper;
	int err;

	err = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN, 1);

	if (err) {
		netdev_err(netdev, "%s: query port ptys failed: %d\n",
			   __func__, err);
		goto err_query_ptys;
	}

	eth_proto_cap   = MLX5_GET(ptys_reg, out, eth_proto_capability);
	eth_proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	eth_proto_oper  = MLX5_GET(ptys_reg, out, eth_proto_oper);
	eth_proto_lp    = MLX5_GET(ptys_reg, out, eth_proto_lp_advertise);

	ethtool_link_ksettings_zero_link_mode(link_ksettings, supported);
	ethtool_link_ksettings_zero_link_mode(link_ksettings, advertising);

	get_supported(eth_proto_cap, link_ksettings);
	get_advertising(eth_proto_admin, 0, 0, link_ksettings);
	get_speed_duplex(netdev, eth_proto_oper, link_ksettings);

	eth_proto_oper = eth_proto_oper ? eth_proto_oper : eth_proto_cap;

	link_ksettings->base.port = get_connector_port(eth_proto_oper);
	get_lp_advertising(eth_proto_lp, link_ksettings);

err_query_ptys:
	return err;
}

static u32 mlx5e_ethtool2ptys_adver_link(const unsigned long *link_modes)
{
	u32 i, ptys_modes = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (bitmap_intersects(ptys2ethtool_table[i].advertised,
				      link_modes,
				      __ETHTOOL_LINK_MODE_MASK_NBITS))
			ptys_modes |= MLX5E_PROT_MASK(i);
	}

	return ptys_modes;
}

static u32 mlx5e_ethtool2ptys_speed_link(u32 speed)
{
	u32 i, speed_links = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (ptys2ethtool_table[i].speed == speed)
			speed_links |= MLX5E_PROT_MASK(i);
	}

	return speed_links;
}

static int mlx5e_set_link_ksettings(struct net_device *netdev,
				    const struct ethtool_link_ksettings *link_ksettings)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 link_modes;
	u32 speed;
	u32 eth_proto_cap, eth_proto_admin;
	enum mlx5_port_status ps;
	int err;

	speed = link_ksettings->base.speed;

	link_modes = link_ksettings->base.autoneg == AUTONEG_ENABLE ?
		mlx5e_ethtool2ptys_adver_link(link_ksettings->link_modes.advertising) :
		mlx5e_ethtool2ptys_speed_link(speed);

	err = mlx5_query_port_proto_cap(mdev, &eth_proto_cap, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto cap failed: %d\n",
			   __func__, err);
		goto out;
	}

	link_modes = link_modes & eth_proto_cap;
	if (!link_modes) {
		netdev_err(netdev, "%s: Not supported link mode(s) requested",
			   __func__);
		err = -EINVAL;
		goto out;
	}

	err = mlx5_query_port_proto_admin(mdev, &eth_proto_admin, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto admin failed: %d\n",
			   __func__, err);
		goto out;
	}

	if (link_modes == eth_proto_admin)
		goto out;

	mlx5_query_port_admin_status(mdev, &ps);
	if (ps == MLX5_PORT_UP)
		mlx5_set_port_admin_status(mdev, MLX5_PORT_DOWN);
	mlx5_set_port_proto(mdev, link_modes, MLX5_PTYS_EN);
	if (ps == MLX5_PORT_UP)
		mlx5_set_port_admin_status(mdev, MLX5_PORT_UP);

out:
	return err;
}

static u32 mlx5e_get_rxfh_key_size(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	return sizeof(priv->params.toeplitz_hash_key);
}

static u32 mlx5e_get_rxfh_indir_size(struct net_device *netdev)
{
	return MLX5E_INDIR_RQT_SIZE;
}

static int mlx5e_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			  u8 *hfunc)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (indir)
		memcpy(indir, priv->params.indirection_rqt,
		       sizeof(priv->params.indirection_rqt));

	if (key)
		memcpy(key, priv->params.toeplitz_hash_key,
		       sizeof(priv->params.toeplitz_hash_key));

	if (hfunc)
		*hfunc = priv->params.rss_hfunc;

	return 0;
}

static int mlx5e_set_rxfh(struct net_device *dev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	bool close_open;
	int err = 0;

	if ((hfunc != ETH_RSS_HASH_NO_CHANGE) &&
	    (hfunc != ETH_RSS_HASH_XOR) &&
	    (hfunc != ETH_RSS_HASH_TOP))
		return -EINVAL;

	mutex_lock(&priv->state_lock);

	if (indir) {
		memcpy(priv->params.indirection_rqt, indir,
		       sizeof(priv->params.indirection_rqt));
		mlx5e_redirect_rqt(priv, MLX5E_INDIRECTION_RQT);
	}

	close_open = (key || (hfunc != ETH_RSS_HASH_NO_CHANGE)) &&
		     test_bit(MLX5E_STATE_OPENED, &priv->state);
	if (close_open)
		mlx5e_close_locked(dev);

	if (key)
		memcpy(priv->params.toeplitz_hash_key, key,
		       sizeof(priv->params.toeplitz_hash_key));

	if (hfunc != ETH_RSS_HASH_NO_CHANGE)
		priv->params.rss_hfunc = hfunc;

	if (close_open)
		err = mlx5e_open_locked(priv->netdev);

	mutex_unlock(&priv->state_lock);

	return err;
}

static int mlx5e_get_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *info, u32 *rule_locs)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err = 0;

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = priv->params.num_channels;
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int mlx5e_get_tunable(struct net_device *dev,
			     const struct ethtool_tunable *tuna,
			     void *data)
{
	const struct mlx5e_priv *priv = netdev_priv(dev);
	int err = 0;

	switch (tuna->id) {
	case ETHTOOL_TX_COPYBREAK:
		*(u32 *)data = priv->params.tx_max_inline;
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static int mlx5e_set_tunable(struct net_device *dev,
			     const struct ethtool_tunable *tuna,
			     const void *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	bool was_opened;
	u32 val;
	int err = 0;

	switch (tuna->id) {
	case ETHTOOL_TX_COPYBREAK:
		val = *(u32 *)data;
		if (val > mlx5e_get_max_inline_cap(mdev)) {
			err = -EINVAL;
			break;
		}

		mutex_lock(&priv->state_lock);

		was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);
		if (was_opened)
			mlx5e_close_locked(dev);

		priv->params.tx_max_inline = val;

		if (was_opened)
			err = mlx5e_open_locked(dev);

		mutex_unlock(&priv->state_lock);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static void mlx5e_get_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pauseparam)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	err = mlx5_query_port_pause(mdev, &pauseparam->rx_pause,
				    &pauseparam->tx_pause);
	if (err) {
		netdev_err(netdev, "%s: mlx5_query_port_pause failed:0x%x\n",
			   __func__, err);
	}
}

static int mlx5e_set_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pauseparam)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int err;

	if (pauseparam->autoneg)
		return -EINVAL;

	err = mlx5_set_port_pause(mdev,
				  pauseparam->rx_pause ? 1 : 0,
				  pauseparam->tx_pause ? 1 : 0);
	if (err) {
		netdev_err(netdev, "%s: mlx5_set_port_pause failed:0x%x\n",
			   __func__, err);
	}

	return err;
}

const struct ethtool_ops mlx5e_ethtool_ops = {
	.get_drvinfo       = mlx5e_get_drvinfo,
	.get_link          = ethtool_op_get_link,
	.get_strings       = mlx5e_get_strings,
	.get_sset_count    = mlx5e_get_sset_count,
	.get_ethtool_stats = mlx5e_get_ethtool_stats,
	.get_ringparam     = mlx5e_get_ringparam,
	.set_ringparam     = mlx5e_set_ringparam,
	.get_channels      = mlx5e_get_channels,
	.set_channels      = mlx5e_set_channels,
	.get_coalesce      = mlx5e_get_coalesce,
	.set_coalesce      = mlx5e_set_coalesce,
	.get_link_ksettings  = mlx5e_get_link_ksettings,
	.set_link_ksettings  = mlx5e_set_link_ksettings,
	.get_rxfh_key_size   = mlx5e_get_rxfh_key_size,
	.get_rxfh_indir_size = mlx5e_get_rxfh_indir_size,
	.get_rxfh          = mlx5e_get_rxfh,
	.set_rxfh          = mlx5e_set_rxfh,
	.get_rxnfc         = mlx5e_get_rxnfc,
	.get_tunable       = mlx5e_get_tunable,
	.set_tunable       = mlx5e_set_tunable,
	.get_pauseparam    = mlx5e_get_pauseparam,
	.set_pauseparam    = mlx5e_set_pauseparam,
};
