package com.example.BaiTech_QuanLyCV.service.imp;

import com.example.BaiTech_QuanLyCV.dto.DotTuyenDungDTO;
import com.example.BaiTech_QuanLyCV.entity.DotTuyenDung;
import com.example.BaiTech_QuanLyCV.entity.NhanVien;
import com.example.BaiTech_QuanLyCV.exception.ResourceNotfound;
import com.example.BaiTech_QuanLyCV.repository.DotTuyenDungRepository;
import com.example.BaiTech_QuanLyCV.repository.NhanVienRepository;
import com.example.BaiTech_QuanLyCV.service.DotTuyenDungService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DotTuyenDungSetviceImp implements DotTuyenDungService {

    private DotTuyenDungRepository dotTuyenDungRepository;

    private NhanVienRepository nhanVienRepository;

    private ModelMapper modelMapper;

    @Autowired
    public DotTuyenDungSetviceImp(DotTuyenDungRepository dotTuyenDungRepository, NhanVienRepository nhanVienRepository, ModelMapper modelMapper) {
        this.dotTuyenDungRepository = dotTuyenDungRepository;
        this.nhanVienRepository = nhanVienRepository;
        this.modelMapper = modelMapper;
    }

    @Override
    public List<DotTuyenDungDTO> getAll() {
        return dotTuyenDungRepository.findAll().stream()
                .map((dotTuyenDung) -> modelMapper.map(dotTuyenDung, DotTuyenDungDTO.class)).collect(Collectors.toList());
    }

    @Override
    public DotTuyenDungDTO getOne(Integer id) {
        return modelMapper.map(dotTuyenDungRepository.findById(id).orElseThrow(() -> new ResourceNotfound("Khong ton tai dơt tuyen dung có id: "+id)),DotTuyenDungDTO.class);

    }

    @Override
    public DotTuyenDungDTO save(DotTuyenDungDTO dotTuyenDungDTO) {
        NhanVien nhanVien=nhanVienRepository.findById(dotTuyenDungDTO.getNhanVienId()).orElseThrow(() -> new ResourceNotfound("Không tồn tại nhan vien có id: "+dotTuyenDungDTO.getNhanVienId()));
        DotTuyenDung dotTuyenDung=modelMapper.map(dotTuyenDungDTO,DotTuyenDung.class);
        dotTuyenDung.setNhanVien(nhanVien);
        dotTuyenDung.setDeletedAt(false);
        DotTuyenDung dotTuyenDungSave=dotTuyenDungRepository.save(dotTuyenDung);
        return modelMapper.map(dotTuyenDungSave,DotTuyenDungDTO.class);
    }

    @Override
    public DotTuyenDungDTO update(DotTuyenDungDTO dotTuyenDungDTO, Integer id) {
        DotTuyenDung dotTuyenDung=dotTuyenDungRepository.findById(id).orElseThrow(() -> new ResourceNotfound("Khong ton tai dơt tuyen dung có id: "+id));
        NhanVien nhanVien=nhanVienRepository.findById(dotTuyenDungDTO.getNhanVienId()).orElseThrow(() -> new ResourceNotfound("Không tồn tại nhan vien có id: "+dotTuyenDungDTO.getNhanVienId()));
        dotTuyenDung.setMaDotTuyenDung(dotTuyenDungDTO.getMaDotTuyenDung());
        dotTuyenDung.setTenDotTuyenDung(dotTuyenDungDTO.getTenDotTuyenDung());
        dotTuyenDung.setNoiDung(dotTuyenDungDTO.getNoiDung());
        dotTuyenDung.setDeadline(dotTuyenDungDTO.getDeadline());
        dotTuyenDung.setNhanVien(nhanVien);
        DotTuyenDung dotTuyenDungUpdate=dotTuyenDungRepository.save(dotTuyenDung);
        return modelMapper.map(dotTuyenDungUpdate,DotTuyenDungDTO.class);
    }

    @Override
    public void delete(Integer id) {
        DotTuyenDung dotTuyenDung=dotTuyenDungRepository.findById(id).orElseThrow(() -> new ResourceNotfound("Khong ton tai dơt tuyen dung có id: "+id));
        dotTuyenDungRepository.softDeleteDotTuyenDung(id);

    }

    @Override
    public Page<DotTuyenDungDTO> searchDotTuyenDung(String maDotTuyenDung, String tenDotTuyenDung, String noiDung, String tenNhanVien, Pageable pageable) {
        Page<DotTuyenDung> dotTuyenDungPage = dotTuyenDungRepository.searchDotTuyenDung(maDotTuyenDung, tenDotTuyenDung, noiDung, tenNhanVien,pageable);

        List<DotTuyenDungDTO> dotTuyenDungDTOS = dotTuyenDungPage.getContent().stream()
                .map((phongBan) ->modelMapper.map(phongBan,DotTuyenDungDTO.class))
                .collect(Collectors.toList());

        return new PageImpl<>(dotTuyenDungDTOS, pageable, dotTuyenDungPage.getTotalElements());
    }
}
