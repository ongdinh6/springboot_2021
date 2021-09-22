package nlu.fit.cellphoneapp.converters;

import nlu.fit.cellphoneapp.others.Link;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class ImageAddressConventer implements AttributeConverter<ImageAddress, String> {
    @Override
    public String convertToDatabaseColumn(ImageAddress imageAddress) {
        return imageAddress.getRelativePath();
    }

    @Override
    public ImageAddress convertToEntityAttribute(String s) {
        return new ImageAddress(Link.HOST, s);
    }
}
