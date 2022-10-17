package com.zerobase.fastlms.admin.service;

import com.zerobase.fastlms.admin.dto.BannerDto;
import com.zerobase.fastlms.admin.model.BannerInput;
import com.zerobase.fastlms.admin.model.BannerParam;

import java.util.List;

public interface BannerService {

    boolean add(BannerInput parameter);

    boolean set(BannerInput parameter);

    List<BannerDto> list(BannerParam parameter);

    BannerDto getById(long id);

    boolean del(String idList);

    List<BannerDto> frontList();

}
