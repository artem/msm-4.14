ifeq ($(CONFIG_BUILD_ARM64_DT_OVERLAY),y)
dtbo-$(CONFIG_MACH_SONY_GRIFFIN) += \
	sm8150-kumano-griffin_generic-overlay.dtbo
dtbo-$(CONFIG_MACH_SONY_GRIFFIN_K) += \
	sm8150-kumano-griffin_k-overlay.dtbo
dtbo-$(CONFIG_MACH_SONY_GRIFFIN_N) += \
	sm8150-kumano-griffin_n-overlay.dtbo
dtbo-$(CONFIG_MACH_SONY_GRIFFIN_S) += \
	sm8150-kumano-griffin_s-overlay.dtbo
dtbo-$(CONFIG_MACH_SONY_BAHAMUT) += \
	sm8150-kumano-bahamut_generic-overlay.dtbo

ifeq ($(CONFIG_MACH_SONY_GRIFFIN),y)
sm8150-kumano-griffin_generic-overlay.dtbo-base := ../qcom/sm8150.dtb ../qcom/sm8150-v2.dtb
endif
ifeq ($(CONFIG_MACH_SONY_GRIFFIN_K),y)
sm8150-kumano-griffin_k-overlay.dtbo-base := ../qcom/sm8150.dtb ../qcom/sm8150-v2.dtb
endif
ifeq ($(CONFIG_MACH_SONY_GRIFFIN_N),y)
sm8150-kumano-griffin_n-overlay.dtbo-base := ../qcom/sm8150.dtb ../qcom/sm8150-v2.dtb
endif
ifeq ($(CONFIG_MACH_SONY_GRIFFIN_S),y)
sm8150-kumano-griffin_s-overlay.dtbo-base := ../qcom/sm8150.dtb ../qcom/sm8150-v2.dtb
endif
ifeq ($(CONFIG_MACH_SONY_BAHAMUT),y)
sm8150-kumano-bahamut_generic-overlay.dtbo-base := ../qcom/sm8150.dtb ../qcom/sm8150-v2.dtb
endif

else
dtb-$(CONFIG_MACH_SONY_GRIFFIN) += \
	sm8150-kumano-griffin_generic.dtb \
	sm8150-v2-kumano-griffin_generic.dtb
dtb-$(CONFIG_MACH_SONY_GRIFFIN_K) += \
	sm8150-kumano-griffin_k.dtb \
	sm8150-v2-kumano-griffin_k.dtb
dtb-$(CONFIG_MACH_SONY_GRIFFIN_N) += \
	sm8150-kumano-griffin_n.dtb \
	sm8150-v2-kumano-griffin_n.dtb
dtb-$(CONFIG_MACH_SONY_GRIFFIN_S) += \
	sm8150-kumano-griffin_s.dtb \
	sm8150-v2-kumano-griffin_s.dtb
dtb-$(CONFIG_MACH_SONY_BAHAMUT) += \
	sm8150-kumano-bahamut_generic.dtb \
	sm8150-v2-kumano-bahamut_generic.dtb
endif

ifeq ($(CONFIG_ARM64),y)
always		:= $(dtb-y)
subdir-y	:= $(dts-dirs)
else
targets += dtbs
targets += $(addprefix ../, $(dtb-y))

$(obj)/../%.dtb: $(src)/%.dts FORCE
	$(call if_changed_dep,dtc)

dtbs: $(addprefix $(obj)/../,$(dtb-y))
endif
clean-files	:= *.dtb *.dtbo
