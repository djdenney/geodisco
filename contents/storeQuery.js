
const storeQuery = async (coordlist) => {
    return `SELECT
                DISTINCT
                ADDRESS_ADDRESS1,
                ADDRESS_CITY,
                ADDRESS_STATE,
                ADDRESS_POSTALCODE,
                ADDRESS_PHONE,
                LOCATION_ID,
                LATITUDE,
                LONGITUDE
            FROM
                default_organization.ORG_LOCATION
            WHERE
                LOCATION_SUB_TYPE_ID = 'StoreRegular'
            AND
	            LOCATION_STATUS_ID = 'Operational'
            AND
            ((LONGITUDE BETWEEN ${coordlist[0].lon < coordlist[180].lon ? coordlist[0].lon : coordlist[180].lon} AND ${coordlist[180].lon > coordlist[0].lon ? coordlist[180].lon : coordlist[0].lon}
                AND
                LATITUDE BETWEEN ${coordlist[0].lat < coordlist[180].lat ? coordlist[0].lat : coordlist[180].lat} AND ${coordlist[180].lat > coordlist[0].lat ? coordlist[180].lat : coordlist[0].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[1].lon < coordlist[181].lon ? coordlist[1].lon : coordlist[181].lon} AND ${coordlist[181].lon > coordlist[1].lon ? coordlist[181].lon : coordlist[1].lon}
                AND
                LATITUDE BETWEEN ${coordlist[1].lat < coordlist[181].lat ? coordlist[1].lat : coordlist[181].lat} AND ${coordlist[181].lat > coordlist[1].lat ? coordlist[181].lat : coordlist[1].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[2].lon < coordlist[182].lon ? coordlist[2].lon : coordlist[182].lon} AND ${coordlist[182].lon > coordlist[2].lon ? coordlist[182].lon : coordlist[2].lon}
                AND
                LATITUDE BETWEEN ${coordlist[2].lat < coordlist[182].lat ? coordlist[2].lat : coordlist[182].lat} AND ${coordlist[182].lat > coordlist[2].lat ? coordlist[182].lat : coordlist[2].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[3].lon < coordlist[183].lon ? coordlist[3].lon : coordlist[183].lon} AND ${coordlist[183].lon > coordlist[3].lon ? coordlist[183].lon : coordlist[3].lon}
                AND
                LATITUDE BETWEEN ${coordlist[3].lat < coordlist[183].lat ? coordlist[3].lat : coordlist[183].lat} AND ${coordlist[183].lat > coordlist[3].lat ? coordlist[183].lat : coordlist[3].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[4].lon < coordlist[184].lon ? coordlist[4].lon : coordlist[184].lon} AND ${coordlist[184].lon > coordlist[4].lon ? coordlist[184].lon : coordlist[4].lon}
                AND
                LATITUDE BETWEEN ${coordlist[4].lat < coordlist[184].lat ? coordlist[4].lat : coordlist[184].lat} AND ${coordlist[184].lat > coordlist[4].lat ? coordlist[184].lat : coordlist[4].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[5].lon < coordlist[185].lon ? coordlist[5].lon : coordlist[185].lon} AND ${coordlist[185].lon > coordlist[5].lon ? coordlist[185].lon : coordlist[5].lon}
                AND
                LATITUDE BETWEEN ${coordlist[5].lat < coordlist[185].lat ? coordlist[5].lat : coordlist[185].lat} AND ${coordlist[185].lat > coordlist[5].lat ? coordlist[185].lat : coordlist[5].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[6].lon < coordlist[186].lon ? coordlist[6].lon : coordlist[186].lon} AND ${coordlist[186].lon > coordlist[6].lon ? coordlist[186].lon : coordlist[6].lon}
                AND
                LATITUDE BETWEEN ${coordlist[6].lat < coordlist[186].lat ? coordlist[6].lat : coordlist[186].lat} AND ${coordlist[186].lat > coordlist[6].lat ? coordlist[186].lat : coordlist[6].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[7].lon < coordlist[187].lon ? coordlist[7].lon : coordlist[187].lon} AND ${coordlist[187].lon > coordlist[7].lon ? coordlist[187].lon : coordlist[7].lon}
                AND
                LATITUDE BETWEEN ${coordlist[7].lat < coordlist[187].lat ? coordlist[7].lat : coordlist[187].lat} AND ${coordlist[187].lat > coordlist[7].lat ? coordlist[187].lat : coordlist[7].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[8].lon < coordlist[188].lon ? coordlist[8].lon : coordlist[188].lon} AND ${coordlist[188].lon > coordlist[8].lon ? coordlist[188].lon : coordlist[8].lon}
                AND
                LATITUDE BETWEEN ${coordlist[8].lat < coordlist[188].lat ? coordlist[8].lat : coordlist[188].lat} AND ${coordlist[188].lat > coordlist[8].lat ? coordlist[188].lat : coordlist[8].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[9].lon < coordlist[189].lon ? coordlist[9].lon : coordlist[189].lon} AND ${coordlist[189].lon > coordlist[9].lon ? coordlist[189].lon : coordlist[9].lon}
                AND
                LATITUDE BETWEEN ${coordlist[9].lat < coordlist[189].lat ? coordlist[9].lat : coordlist[189].lat} AND ${coordlist[189].lat > coordlist[9].lat ? coordlist[189].lat : coordlist[9].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[10].lon < coordlist[190].lon ? coordlist[10].lon : coordlist[190].lon} AND ${coordlist[190].lon > coordlist[10].lon ? coordlist[190].lon : coordlist[10].lon}
                AND
                LATITUDE BETWEEN ${coordlist[10].lat < coordlist[190].lat ? coordlist[10].lat : coordlist[190].lat} AND ${coordlist[190].lat > coordlist[10].lat ? coordlist[190].lat : coordlist[10].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[11].lon < coordlist[191].lon ? coordlist[11].lon : coordlist[191].lon} AND ${coordlist[191].lon > coordlist[11].lon ? coordlist[191].lon : coordlist[11].lon}
                AND
                LATITUDE BETWEEN ${coordlist[11].lat < coordlist[191].lat ? coordlist[11].lat : coordlist[191].lat} AND ${coordlist[191].lat > coordlist[11].lat ? coordlist[191].lat : coordlist[11].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[12].lon < coordlist[192].lon ? coordlist[12].lon : coordlist[192].lon} AND ${coordlist[192].lon > coordlist[12].lon ? coordlist[192].lon : coordlist[12].lon}
                AND
                LATITUDE BETWEEN ${coordlist[12].lat < coordlist[192].lat ? coordlist[12].lat : coordlist[192].lat} AND ${coordlist[192].lat > coordlist[12].lat ? coordlist[192].lat : coordlist[12].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[13].lon < coordlist[193].lon ? coordlist[13].lon : coordlist[193].lon} AND ${coordlist[193].lon > coordlist[13].lon ? coordlist[193].lon : coordlist[13].lon}
                AND
                LATITUDE BETWEEN ${coordlist[13].lat < coordlist[193].lat ? coordlist[13].lat : coordlist[193].lat} AND ${coordlist[193].lat > coordlist[13].lat ? coordlist[193].lat : coordlist[13].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[14].lon < coordlist[194].lon ? coordlist[14].lon : coordlist[194].lon} AND ${coordlist[194].lon > coordlist[14].lon ? coordlist[194].lon : coordlist[14].lon}
                AND
                LATITUDE BETWEEN ${coordlist[14].lat < coordlist[194].lat ? coordlist[14].lat : coordlist[194].lat} AND ${coordlist[194].lat > coordlist[14].lat ? coordlist[194].lat : coordlist[14].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[15].lon < coordlist[195].lon ? coordlist[15].lon : coordlist[195].lon} AND ${coordlist[195].lon > coordlist[15].lon ? coordlist[195].lon : coordlist[15].lon}
                AND
                LATITUDE BETWEEN ${coordlist[15].lat < coordlist[195].lat ? coordlist[15].lat : coordlist[195].lat} AND ${coordlist[195].lat > coordlist[15].lat ? coordlist[195].lat : coordlist[15].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[16].lon < coordlist[196].lon ? coordlist[16].lon : coordlist[196].lon} AND ${coordlist[196].lon > coordlist[16].lon ? coordlist[196].lon : coordlist[16].lon}
                AND
                LATITUDE BETWEEN ${coordlist[16].lat < coordlist[196].lat ? coordlist[16].lat : coordlist[196].lat} AND ${coordlist[196].lat > coordlist[16].lat ? coordlist[196].lat : coordlist[16].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[17].lon < coordlist[197].lon ? coordlist[17].lon : coordlist[197].lon} AND ${coordlist[197].lon > coordlist[17].lon ? coordlist[197].lon : coordlist[17].lon}
                AND
                LATITUDE BETWEEN ${coordlist[17].lat < coordlist[197].lat ? coordlist[17].lat : coordlist[197].lat} AND ${coordlist[197].lat > coordlist[17].lat ? coordlist[197].lat : coordlist[17].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[18].lon < coordlist[198].lon ? coordlist[18].lon : coordlist[198].lon} AND ${coordlist[198].lon > coordlist[18].lon ? coordlist[198].lon : coordlist[18].lon}
                AND
                LATITUDE BETWEEN ${coordlist[18].lat < coordlist[198].lat ? coordlist[18].lat : coordlist[198].lat} AND ${coordlist[198].lat > coordlist[18].lat ? coordlist[198].lat : coordlist[18].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[19].lon < coordlist[199].lon ? coordlist[19].lon : coordlist[199].lon} AND ${coordlist[199].lon > coordlist[19].lon ? coordlist[199].lon : coordlist[19].lon}
                AND
                LATITUDE BETWEEN ${coordlist[19].lat < coordlist[199].lat ? coordlist[19].lat : coordlist[199].lat} AND ${coordlist[199].lat > coordlist[19].lat ? coordlist[199].lat : coordlist[19].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[20].lon < coordlist[200].lon ? coordlist[20].lon : coordlist[200].lon} AND ${coordlist[200].lon > coordlist[20].lon ? coordlist[200].lon : coordlist[20].lon}
                AND
                LATITUDE BETWEEN ${coordlist[20].lat < coordlist[200].lat ? coordlist[20].lat : coordlist[200].lat} AND ${coordlist[200].lat > coordlist[20].lat ? coordlist[200].lat : coordlist[20].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[21].lon < coordlist[201].lon ? coordlist[21].lon : coordlist[201].lon} AND ${coordlist[201].lon > coordlist[21].lon ? coordlist[201].lon : coordlist[21].lon}
                AND
                LATITUDE BETWEEN ${coordlist[21].lat < coordlist[201].lat ? coordlist[21].lat : coordlist[201].lat} AND ${coordlist[201].lat > coordlist[21].lat ? coordlist[201].lat : coordlist[21].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[22].lon < coordlist[202].lon ? coordlist[22].lon : coordlist[202].lon} AND ${coordlist[202].lon > coordlist[22].lon ? coordlist[202].lon : coordlist[22].lon}
                AND
                LATITUDE BETWEEN ${coordlist[22].lat < coordlist[202].lat ? coordlist[22].lat : coordlist[202].lat} AND ${coordlist[202].lat > coordlist[22].lat ? coordlist[202].lat : coordlist[22].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[23].lon < coordlist[203].lon ? coordlist[23].lon : coordlist[203].lon} AND ${coordlist[203].lon > coordlist[23].lon ? coordlist[203].lon : coordlist[23].lon}
                AND
                LATITUDE BETWEEN ${coordlist[23].lat < coordlist[203].lat ? coordlist[23].lat : coordlist[203].lat} AND ${coordlist[203].lat > coordlist[23].lat ? coordlist[203].lat : coordlist[23].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[24].lon < coordlist[204].lon ? coordlist[24].lon : coordlist[204].lon} AND ${coordlist[204].lon > coordlist[24].lon ? coordlist[204].lon : coordlist[24].lon}
                AND
                LATITUDE BETWEEN ${coordlist[24].lat < coordlist[204].lat ? coordlist[24].lat : coordlist[204].lat} AND ${coordlist[204].lat > coordlist[24].lat ? coordlist[204].lat : coordlist[24].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[25].lon < coordlist[205].lon ? coordlist[25].lon : coordlist[205].lon} AND ${coordlist[205].lon > coordlist[25].lon ? coordlist[205].lon : coordlist[25].lon}
                AND
                LATITUDE BETWEEN ${coordlist[25].lat < coordlist[205].lat ? coordlist[25].lat : coordlist[205].lat} AND ${coordlist[205].lat > coordlist[25].lat ? coordlist[205].lat : coordlist[25].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[26].lon < coordlist[206].lon ? coordlist[26].lon : coordlist[206].lon} AND ${coordlist[206].lon > coordlist[26].lon ? coordlist[206].lon : coordlist[26].lon}
                AND
                LATITUDE BETWEEN ${coordlist[26].lat < coordlist[206].lat ? coordlist[26].lat : coordlist[206].lat} AND ${coordlist[206].lat > coordlist[26].lat ? coordlist[206].lat : coordlist[26].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[27].lon < coordlist[207].lon ? coordlist[27].lon : coordlist[207].lon} AND ${coordlist[207].lon > coordlist[27].lon ? coordlist[207].lon : coordlist[27].lon}
                AND
                LATITUDE BETWEEN ${coordlist[27].lat < coordlist[207].lat ? coordlist[27].lat : coordlist[207].lat} AND ${coordlist[207].lat > coordlist[27].lat ? coordlist[207].lat : coordlist[27].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[28].lon < coordlist[208].lon ? coordlist[28].lon : coordlist[208].lon} AND ${coordlist[208].lon > coordlist[28].lon ? coordlist[208].lon : coordlist[28].lon}
                AND
                LATITUDE BETWEEN ${coordlist[28].lat < coordlist[208].lat ? coordlist[28].lat : coordlist[208].lat} AND ${coordlist[208].lat > coordlist[28].lat ? coordlist[208].lat : coordlist[28].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[29].lon < coordlist[209].lon ? coordlist[29].lon : coordlist[209].lon} AND ${coordlist[209].lon > coordlist[29].lon ? coordlist[209].lon : coordlist[29].lon}
                AND
                LATITUDE BETWEEN ${coordlist[29].lat < coordlist[209].lat ? coordlist[29].lat : coordlist[209].lat} AND ${coordlist[209].lat > coordlist[29].lat ? coordlist[209].lat : coordlist[29].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[30].lon < coordlist[210].lon ? coordlist[30].lon : coordlist[210].lon} AND ${coordlist[210].lon > coordlist[30].lon ? coordlist[210].lon : coordlist[30].lon}
                AND
                LATITUDE BETWEEN ${coordlist[30].lat < coordlist[210].lat ? coordlist[30].lat : coordlist[210].lat} AND ${coordlist[210].lat > coordlist[30].lat ? coordlist[210].lat : coordlist[30].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[31].lon < coordlist[211].lon ? coordlist[31].lon : coordlist[211].lon} AND ${coordlist[211].lon > coordlist[31].lon ? coordlist[211].lon : coordlist[31].lon}
                AND
                LATITUDE BETWEEN ${coordlist[31].lat < coordlist[211].lat ? coordlist[31].lat : coordlist[211].lat} AND ${coordlist[211].lat > coordlist[31].lat ? coordlist[211].lat : coordlist[31].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[32].lon < coordlist[212].lon ? coordlist[32].lon : coordlist[212].lon} AND ${coordlist[212].lon > coordlist[32].lon ? coordlist[212].lon : coordlist[32].lon}
                AND
                LATITUDE BETWEEN ${coordlist[32].lat < coordlist[212].lat ? coordlist[32].lat : coordlist[212].lat} AND ${coordlist[212].lat > coordlist[32].lat ? coordlist[212].lat : coordlist[32].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[33].lon < coordlist[213].lon ? coordlist[33].lon : coordlist[213].lon} AND ${coordlist[213].lon > coordlist[33].lon ? coordlist[213].lon : coordlist[33].lon}
                AND
                LATITUDE BETWEEN ${coordlist[33].lat < coordlist[213].lat ? coordlist[33].lat : coordlist[213].lat} AND ${coordlist[213].lat > coordlist[33].lat ? coordlist[213].lat : coordlist[33].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[34].lon < coordlist[214].lon ? coordlist[34].lon : coordlist[214].lon} AND ${coordlist[214].lon > coordlist[34].lon ? coordlist[214].lon : coordlist[34].lon}
                AND
                LATITUDE BETWEEN ${coordlist[34].lat < coordlist[214].lat ? coordlist[34].lat : coordlist[214].lat} AND ${coordlist[214].lat > coordlist[34].lat ? coordlist[214].lat : coordlist[34].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[35].lon < coordlist[215].lon ? coordlist[35].lon : coordlist[215].lon} AND ${coordlist[215].lon > coordlist[35].lon ? coordlist[215].lon : coordlist[35].lon}
                AND
                LATITUDE BETWEEN ${coordlist[35].lat < coordlist[215].lat ? coordlist[35].lat : coordlist[215].lat} AND ${coordlist[215].lat > coordlist[35].lat ? coordlist[215].lat : coordlist[35].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[36].lon < coordlist[216].lon ? coordlist[36].lon : coordlist[216].lon} AND ${coordlist[216].lon > coordlist[36].lon ? coordlist[216].lon : coordlist[36].lon}
                AND
                LATITUDE BETWEEN ${coordlist[36].lat < coordlist[216].lat ? coordlist[36].lat : coordlist[216].lat} AND ${coordlist[216].lat > coordlist[36].lat ? coordlist[216].lat : coordlist[36].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[37].lon < coordlist[217].lon ? coordlist[37].lon : coordlist[217].lon} AND ${coordlist[217].lon > coordlist[37].lon ? coordlist[217].lon : coordlist[37].lon}
                AND
                LATITUDE BETWEEN ${coordlist[37].lat < coordlist[217].lat ? coordlist[37].lat : coordlist[217].lat} AND ${coordlist[217].lat > coordlist[37].lat ? coordlist[217].lat : coordlist[37].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[38].lon < coordlist[218].lon ? coordlist[38].lon : coordlist[218].lon} AND ${coordlist[218].lon > coordlist[38].lon ? coordlist[218].lon : coordlist[38].lon}
                AND
                LATITUDE BETWEEN ${coordlist[38].lat < coordlist[218].lat ? coordlist[38].lat : coordlist[218].lat} AND ${coordlist[218].lat > coordlist[38].lat ? coordlist[218].lat : coordlist[38].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[39].lon < coordlist[219].lon ? coordlist[39].lon : coordlist[219].lon} AND ${coordlist[219].lon > coordlist[39].lon ? coordlist[219].lon : coordlist[39].lon}
                AND
                LATITUDE BETWEEN ${coordlist[39].lat < coordlist[219].lat ? coordlist[39].lat : coordlist[219].lat} AND ${coordlist[219].lat > coordlist[39].lat ? coordlist[219].lat : coordlist[39].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[40].lon < coordlist[220].lon ? coordlist[40].lon : coordlist[220].lon} AND ${coordlist[220].lon > coordlist[40].lon ? coordlist[220].lon : coordlist[40].lon}
                AND
                LATITUDE BETWEEN ${coordlist[40].lat < coordlist[220].lat ? coordlist[40].lat : coordlist[220].lat} AND ${coordlist[220].lat > coordlist[40].lat ? coordlist[220].lat : coordlist[40].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[41].lon < coordlist[221].lon ? coordlist[41].lon : coordlist[221].lon} AND ${coordlist[221].lon > coordlist[41].lon ? coordlist[221].lon : coordlist[41].lon}
                AND
                LATITUDE BETWEEN ${coordlist[41].lat < coordlist[221].lat ? coordlist[41].lat : coordlist[221].lat} AND ${coordlist[221].lat > coordlist[41].lat ? coordlist[221].lat : coordlist[41].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[42].lon < coordlist[222].lon ? coordlist[42].lon : coordlist[222].lon} AND ${coordlist[222].lon > coordlist[42].lon ? coordlist[222].lon : coordlist[42].lon}
                AND
                LATITUDE BETWEEN ${coordlist[42].lat < coordlist[222].lat ? coordlist[42].lat : coordlist[222].lat} AND ${coordlist[222].lat > coordlist[42].lat ? coordlist[222].lat : coordlist[42].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[43].lon < coordlist[223].lon ? coordlist[43].lon : coordlist[223].lon} AND ${coordlist[223].lon > coordlist[43].lon ? coordlist[223].lon : coordlist[43].lon}
                AND
                LATITUDE BETWEEN ${coordlist[43].lat < coordlist[223].lat ? coordlist[43].lat : coordlist[223].lat} AND ${coordlist[223].lat > coordlist[43].lat ? coordlist[223].lat : coordlist[43].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[44].lon < coordlist[224].lon ? coordlist[44].lon : coordlist[224].lon} AND ${coordlist[224].lon > coordlist[44].lon ? coordlist[224].lon : coordlist[44].lon}
                AND
                LATITUDE BETWEEN ${coordlist[44].lat < coordlist[224].lat ? coordlist[44].lat : coordlist[224].lat} AND ${coordlist[224].lat > coordlist[44].lat ? coordlist[224].lat : coordlist[44].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[45].lon < coordlist[225].lon ? coordlist[45].lon : coordlist[225].lon} AND ${coordlist[225].lon > coordlist[45].lon ? coordlist[225].lon : coordlist[45].lon}
                AND
                LATITUDE BETWEEN ${coordlist[45].lat < coordlist[225].lat ? coordlist[45].lat : coordlist[225].lat} AND ${coordlist[225].lat > coordlist[45].lat ? coordlist[225].lat : coordlist[45].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[46].lon < coordlist[226].lon ? coordlist[46].lon : coordlist[226].lon} AND ${coordlist[226].lon > coordlist[46].lon ? coordlist[226].lon : coordlist[46].lon}
                AND
                LATITUDE BETWEEN ${coordlist[46].lat < coordlist[226].lat ? coordlist[46].lat : coordlist[226].lat} AND ${coordlist[226].lat > coordlist[46].lat ? coordlist[226].lat : coordlist[46].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[47].lon < coordlist[227].lon ? coordlist[47].lon : coordlist[227].lon} AND ${coordlist[227].lon > coordlist[47].lon ? coordlist[227].lon : coordlist[47].lon}
                AND
                LATITUDE BETWEEN ${coordlist[47].lat < coordlist[227].lat ? coordlist[47].lat : coordlist[227].lat} AND ${coordlist[227].lat > coordlist[47].lat ? coordlist[227].lat : coordlist[47].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[48].lon < coordlist[228].lon ? coordlist[48].lon : coordlist[228].lon} AND ${coordlist[228].lon > coordlist[48].lon ? coordlist[228].lon : coordlist[48].lon}
                AND
                LATITUDE BETWEEN ${coordlist[48].lat < coordlist[228].lat ? coordlist[48].lat : coordlist[228].lat} AND ${coordlist[228].lat > coordlist[48].lat ? coordlist[228].lat : coordlist[48].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[49].lon < coordlist[229].lon ? coordlist[49].lon : coordlist[229].lon} AND ${coordlist[229].lon > coordlist[49].lon ? coordlist[229].lon : coordlist[49].lon}
                AND
                LATITUDE BETWEEN ${coordlist[49].lat < coordlist[229].lat ? coordlist[49].lat : coordlist[229].lat} AND ${coordlist[229].lat > coordlist[49].lat ? coordlist[229].lat : coordlist[49].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[50].lon < coordlist[230].lon ? coordlist[50].lon : coordlist[230].lon} AND ${coordlist[230].lon > coordlist[50].lon ? coordlist[230].lon : coordlist[50].lon}
                AND
                LATITUDE BETWEEN ${coordlist[50].lat < coordlist[230].lat ? coordlist[50].lat : coordlist[230].lat} AND ${coordlist[230].lat > coordlist[50].lat ? coordlist[230].lat : coordlist[50].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[51].lon < coordlist[231].lon ? coordlist[51].lon : coordlist[231].lon} AND ${coordlist[231].lon > coordlist[51].lon ? coordlist[231].lon : coordlist[51].lon}
                AND
                LATITUDE BETWEEN ${coordlist[51].lat < coordlist[231].lat ? coordlist[51].lat : coordlist[231].lat} AND ${coordlist[231].lat > coordlist[51].lat ? coordlist[231].lat : coordlist[51].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[52].lon < coordlist[232].lon ? coordlist[52].lon : coordlist[232].lon} AND ${coordlist[232].lon > coordlist[52].lon ? coordlist[232].lon : coordlist[52].lon}
                AND
                LATITUDE BETWEEN ${coordlist[52].lat < coordlist[232].lat ? coordlist[52].lat : coordlist[232].lat} AND ${coordlist[232].lat > coordlist[52].lat ? coordlist[232].lat : coordlist[52].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[53].lon < coordlist[233].lon ? coordlist[53].lon : coordlist[233].lon} AND ${coordlist[233].lon > coordlist[53].lon ? coordlist[233].lon : coordlist[53].lon}
                AND
                LATITUDE BETWEEN ${coordlist[53].lat < coordlist[233].lat ? coordlist[53].lat : coordlist[233].lat} AND ${coordlist[233].lat > coordlist[53].lat ? coordlist[233].lat : coordlist[53].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[54].lon < coordlist[234].lon ? coordlist[54].lon : coordlist[234].lon} AND ${coordlist[234].lon > coordlist[54].lon ? coordlist[234].lon : coordlist[54].lon}
                AND
                LATITUDE BETWEEN ${coordlist[54].lat < coordlist[234].lat ? coordlist[54].lat : coordlist[234].lat} AND ${coordlist[234].lat > coordlist[54].lat ? coordlist[234].lat : coordlist[54].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[55].lon < coordlist[235].lon ? coordlist[55].lon : coordlist[235].lon} AND ${coordlist[235].lon > coordlist[55].lon ? coordlist[235].lon : coordlist[55].lon}
                AND
                LATITUDE BETWEEN ${coordlist[55].lat < coordlist[235].lat ? coordlist[55].lat : coordlist[235].lat} AND ${coordlist[235].lat > coordlist[55].lat ? coordlist[235].lat : coordlist[55].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[56].lon < coordlist[236].lon ? coordlist[56].lon : coordlist[236].lon} AND ${coordlist[236].lon > coordlist[56].lon ? coordlist[236].lon : coordlist[56].lon}
                AND
                LATITUDE BETWEEN ${coordlist[56].lat < coordlist[236].lat ? coordlist[56].lat : coordlist[236].lat} AND ${coordlist[236].lat > coordlist[56].lat ? coordlist[236].lat : coordlist[56].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[57].lon < coordlist[237].lon ? coordlist[57].lon : coordlist[237].lon} AND ${coordlist[237].lon > coordlist[57].lon ? coordlist[237].lon : coordlist[57].lon}
                AND
                LATITUDE BETWEEN ${coordlist[57].lat < coordlist[237].lat ? coordlist[57].lat : coordlist[237].lat} AND ${coordlist[237].lat > coordlist[57].lat ? coordlist[237].lat : coordlist[57].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[58].lon < coordlist[238].lon ? coordlist[58].lon : coordlist[238].lon} AND ${coordlist[238].lon > coordlist[58].lon ? coordlist[238].lon : coordlist[58].lon}
                AND
                LATITUDE BETWEEN ${coordlist[58].lat < coordlist[238].lat ? coordlist[58].lat : coordlist[238].lat} AND ${coordlist[238].lat > coordlist[58].lat ? coordlist[238].lat : coordlist[58].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[59].lon < coordlist[239].lon ? coordlist[59].lon : coordlist[239].lon} AND ${coordlist[239].lon > coordlist[59].lon ? coordlist[239].lon : coordlist[59].lon}
                AND
                LATITUDE BETWEEN ${coordlist[59].lat < coordlist[239].lat ? coordlist[59].lat : coordlist[239].lat} AND ${coordlist[239].lat > coordlist[59].lat ? coordlist[239].lat : coordlist[59].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[60].lon < coordlist[240].lon ? coordlist[60].lon : coordlist[240].lon} AND ${coordlist[240].lon > coordlist[60].lon ? coordlist[240].lon : coordlist[60].lon}
                AND
                LATITUDE BETWEEN ${coordlist[60].lat < coordlist[240].lat ? coordlist[60].lat : coordlist[240].lat} AND ${coordlist[240].lat > coordlist[60].lat ? coordlist[240].lat : coordlist[60].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[61].lon < coordlist[241].lon ? coordlist[61].lon : coordlist[241].lon} AND ${coordlist[241].lon > coordlist[61].lon ? coordlist[241].lon : coordlist[61].lon}
                AND
                LATITUDE BETWEEN ${coordlist[61].lat < coordlist[241].lat ? coordlist[61].lat : coordlist[241].lat} AND ${coordlist[241].lat > coordlist[61].lat ? coordlist[241].lat : coordlist[61].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[62].lon < coordlist[242].lon ? coordlist[62].lon : coordlist[242].lon} AND ${coordlist[242].lon > coordlist[62].lon ? coordlist[242].lon : coordlist[62].lon}
                AND
                LATITUDE BETWEEN ${coordlist[62].lat < coordlist[242].lat ? coordlist[62].lat : coordlist[242].lat} AND ${coordlist[242].lat > coordlist[62].lat ? coordlist[242].lat : coordlist[62].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[63].lon < coordlist[243].lon ? coordlist[63].lon : coordlist[243].lon} AND ${coordlist[243].lon > coordlist[63].lon ? coordlist[243].lon : coordlist[63].lon}
                AND
                LATITUDE BETWEEN ${coordlist[63].lat < coordlist[243].lat ? coordlist[63].lat : coordlist[243].lat} AND ${coordlist[243].lat > coordlist[63].lat ? coordlist[243].lat : coordlist[63].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[64].lon < coordlist[244].lon ? coordlist[64].lon : coordlist[244].lon} AND ${coordlist[244].lon > coordlist[64].lon ? coordlist[244].lon : coordlist[64].lon}
                AND
                LATITUDE BETWEEN ${coordlist[64].lat < coordlist[244].lat ? coordlist[64].lat : coordlist[244].lat} AND ${coordlist[244].lat > coordlist[64].lat ? coordlist[244].lat : coordlist[64].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[65].lon < coordlist[245].lon ? coordlist[65].lon : coordlist[245].lon} AND ${coordlist[245].lon > coordlist[65].lon ? coordlist[245].lon : coordlist[65].lon}
                AND
                LATITUDE BETWEEN ${coordlist[65].lat < coordlist[245].lat ? coordlist[65].lat : coordlist[245].lat} AND ${coordlist[245].lat > coordlist[65].lat ? coordlist[245].lat : coordlist[65].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[66].lon < coordlist[246].lon ? coordlist[66].lon : coordlist[246].lon} AND ${coordlist[246].lon > coordlist[66].lon ? coordlist[246].lon : coordlist[66].lon}
                AND
                LATITUDE BETWEEN ${coordlist[66].lat < coordlist[246].lat ? coordlist[66].lat : coordlist[246].lat} AND ${coordlist[246].lat > coordlist[66].lat ? coordlist[246].lat : coordlist[66].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[67].lon < coordlist[247].lon ? coordlist[67].lon : coordlist[247].lon} AND ${coordlist[247].lon > coordlist[67].lon ? coordlist[247].lon : coordlist[67].lon}
                AND
                LATITUDE BETWEEN ${coordlist[67].lat < coordlist[247].lat ? coordlist[67].lat : coordlist[247].lat} AND ${coordlist[247].lat > coordlist[67].lat ? coordlist[247].lat : coordlist[67].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[68].lon < coordlist[248].lon ? coordlist[68].lon : coordlist[248].lon} AND ${coordlist[248].lon > coordlist[68].lon ? coordlist[248].lon : coordlist[68].lon}
                AND
                LATITUDE BETWEEN ${coordlist[68].lat < coordlist[248].lat ? coordlist[68].lat : coordlist[248].lat} AND ${coordlist[248].lat > coordlist[68].lat ? coordlist[248].lat : coordlist[68].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[69].lon < coordlist[249].lon ? coordlist[69].lon : coordlist[249].lon} AND ${coordlist[249].lon > coordlist[69].lon ? coordlist[249].lon : coordlist[69].lon}
                AND
                LATITUDE BETWEEN ${coordlist[69].lat < coordlist[249].lat ? coordlist[69].lat : coordlist[249].lat} AND ${coordlist[249].lat > coordlist[69].lat ? coordlist[249].lat : coordlist[69].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[70].lon < coordlist[250].lon ? coordlist[70].lon : coordlist[250].lon} AND ${coordlist[250].lon > coordlist[70].lon ? coordlist[250].lon : coordlist[70].lon}
                AND
                LATITUDE BETWEEN ${coordlist[70].lat < coordlist[250].lat ? coordlist[70].lat : coordlist[250].lat} AND ${coordlist[250].lat > coordlist[70].lat ? coordlist[250].lat : coordlist[70].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[71].lon < coordlist[251].lon ? coordlist[71].lon : coordlist[251].lon} AND ${coordlist[251].lon > coordlist[71].lon ? coordlist[251].lon : coordlist[71].lon}
                AND
                LATITUDE BETWEEN ${coordlist[71].lat < coordlist[251].lat ? coordlist[71].lat : coordlist[251].lat} AND ${coordlist[251].lat > coordlist[71].lat ? coordlist[251].lat : coordlist[71].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[72].lon < coordlist[252].lon ? coordlist[72].lon : coordlist[252].lon} AND ${coordlist[252].lon > coordlist[72].lon ? coordlist[252].lon : coordlist[72].lon}
                AND
                LATITUDE BETWEEN ${coordlist[72].lat < coordlist[252].lat ? coordlist[72].lat : coordlist[252].lat} AND ${coordlist[252].lat > coordlist[72].lat ? coordlist[252].lat : coordlist[72].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[73].lon < coordlist[253].lon ? coordlist[73].lon : coordlist[253].lon} AND ${coordlist[253].lon > coordlist[73].lon ? coordlist[253].lon : coordlist[73].lon}
                AND
                LATITUDE BETWEEN ${coordlist[73].lat < coordlist[253].lat ? coordlist[73].lat : coordlist[253].lat} AND ${coordlist[253].lat > coordlist[73].lat ? coordlist[253].lat : coordlist[73].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[74].lon < coordlist[254].lon ? coordlist[74].lon : coordlist[254].lon} AND ${coordlist[254].lon > coordlist[74].lon ? coordlist[254].lon : coordlist[74].lon}
                AND
                LATITUDE BETWEEN ${coordlist[74].lat < coordlist[254].lat ? coordlist[74].lat : coordlist[254].lat} AND ${coordlist[254].lat > coordlist[74].lat ? coordlist[254].lat : coordlist[74].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[75].lon < coordlist[255].lon ? coordlist[75].lon : coordlist[255].lon} AND ${coordlist[255].lon > coordlist[75].lon ? coordlist[255].lon : coordlist[75].lon}
                AND
                LATITUDE BETWEEN ${coordlist[75].lat < coordlist[255].lat ? coordlist[75].lat : coordlist[255].lat} AND ${coordlist[255].lat > coordlist[75].lat ? coordlist[255].lat : coordlist[75].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[76].lon < coordlist[256].lon ? coordlist[76].lon : coordlist[256].lon} AND ${coordlist[256].lon > coordlist[76].lon ? coordlist[256].lon : coordlist[76].lon}
                AND
                LATITUDE BETWEEN ${coordlist[76].lat < coordlist[256].lat ? coordlist[76].lat : coordlist[256].lat} AND ${coordlist[256].lat > coordlist[76].lat ? coordlist[256].lat : coordlist[76].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[77].lon < coordlist[257].lon ? coordlist[77].lon : coordlist[257].lon} AND ${coordlist[257].lon > coordlist[77].lon ? coordlist[257].lon : coordlist[77].lon}
                AND
                LATITUDE BETWEEN ${coordlist[77].lat < coordlist[257].lat ? coordlist[77].lat : coordlist[257].lat} AND ${coordlist[257].lat > coordlist[77].lat ? coordlist[257].lat : coordlist[77].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[78].lon < coordlist[258].lon ? coordlist[78].lon : coordlist[258].lon} AND ${coordlist[258].lon > coordlist[78].lon ? coordlist[258].lon : coordlist[78].lon}
                AND
                LATITUDE BETWEEN ${coordlist[78].lat < coordlist[258].lat ? coordlist[78].lat : coordlist[258].lat} AND ${coordlist[258].lat > coordlist[78].lat ? coordlist[258].lat : coordlist[78].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[79].lon < coordlist[259].lon ? coordlist[79].lon : coordlist[259].lon} AND ${coordlist[259].lon > coordlist[79].lon ? coordlist[259].lon : coordlist[79].lon}
                AND
                LATITUDE BETWEEN ${coordlist[79].lat < coordlist[259].lat ? coordlist[79].lat : coordlist[259].lat} AND ${coordlist[259].lat > coordlist[79].lat ? coordlist[259].lat : coordlist[79].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[80].lon < coordlist[260].lon ? coordlist[80].lon : coordlist[260].lon} AND ${coordlist[260].lon > coordlist[80].lon ? coordlist[260].lon : coordlist[80].lon}
                AND
                LATITUDE BETWEEN ${coordlist[80].lat < coordlist[260].lat ? coordlist[80].lat : coordlist[260].lat} AND ${coordlist[260].lat > coordlist[80].lat ? coordlist[260].lat : coordlist[80].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[81].lon < coordlist[261].lon ? coordlist[81].lon : coordlist[261].lon} AND ${coordlist[261].lon > coordlist[81].lon ? coordlist[261].lon : coordlist[81].lon}
                AND
                LATITUDE BETWEEN ${coordlist[81].lat < coordlist[261].lat ? coordlist[81].lat : coordlist[261].lat} AND ${coordlist[261].lat > coordlist[81].lat ? coordlist[261].lat : coordlist[81].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[82].lon < coordlist[262].lon ? coordlist[82].lon : coordlist[262].lon} AND ${coordlist[262].lon > coordlist[82].lon ? coordlist[262].lon : coordlist[82].lon}
                AND
                LATITUDE BETWEEN ${coordlist[82].lat < coordlist[262].lat ? coordlist[82].lat : coordlist[262].lat} AND ${coordlist[262].lat > coordlist[82].lat ? coordlist[262].lat : coordlist[82].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[83].lon < coordlist[263].lon ? coordlist[83].lon : coordlist[263].lon} AND ${coordlist[263].lon > coordlist[83].lon ? coordlist[263].lon : coordlist[83].lon}
                AND
                LATITUDE BETWEEN ${coordlist[83].lat < coordlist[263].lat ? coordlist[83].lat : coordlist[263].lat} AND ${coordlist[263].lat > coordlist[83].lat ? coordlist[263].lat : coordlist[83].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[84].lon < coordlist[264].lon ? coordlist[84].lon : coordlist[264].lon} AND ${coordlist[264].lon > coordlist[84].lon ? coordlist[264].lon : coordlist[84].lon}
                AND
                LATITUDE BETWEEN ${coordlist[84].lat < coordlist[264].lat ? coordlist[84].lat : coordlist[264].lat} AND ${coordlist[264].lat > coordlist[84].lat ? coordlist[264].lat : coordlist[84].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[85].lon < coordlist[265].lon ? coordlist[85].lon : coordlist[265].lon} AND ${coordlist[265].lon > coordlist[85].lon ? coordlist[265].lon : coordlist[85].lon}
                AND
                LATITUDE BETWEEN ${coordlist[85].lat < coordlist[265].lat ? coordlist[85].lat : coordlist[265].lat} AND ${coordlist[265].lat > coordlist[85].lat ? coordlist[265].lat : coordlist[85].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[86].lon < coordlist[266].lon ? coordlist[86].lon : coordlist[266].lon} AND ${coordlist[266].lon > coordlist[86].lon ? coordlist[266].lon : coordlist[86].lon}
                AND
                LATITUDE BETWEEN ${coordlist[86].lat < coordlist[266].lat ? coordlist[86].lat : coordlist[266].lat} AND ${coordlist[266].lat > coordlist[86].lat ? coordlist[266].lat : coordlist[86].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[87].lon < coordlist[267].lon ? coordlist[87].lon : coordlist[267].lon} AND ${coordlist[267].lon > coordlist[87].lon ? coordlist[267].lon : coordlist[87].lon}
                AND
                LATITUDE BETWEEN ${coordlist[87].lat < coordlist[267].lat ? coordlist[87].lat : coordlist[267].lat} AND ${coordlist[267].lat > coordlist[87].lat ? coordlist[267].lat : coordlist[87].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[88].lon < coordlist[268].lon ? coordlist[88].lon : coordlist[268].lon} AND ${coordlist[268].lon > coordlist[88].lon ? coordlist[268].lon : coordlist[88].lon}
                AND
                LATITUDE BETWEEN ${coordlist[88].lat < coordlist[268].lat ? coordlist[88].lat : coordlist[268].lat} AND ${coordlist[268].lat > coordlist[88].lat ? coordlist[268].lat : coordlist[88].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[89].lon < coordlist[269].lon ? coordlist[89].lon : coordlist[269].lon} AND ${coordlist[269].lon > coordlist[89].lon ? coordlist[269].lon : coordlist[89].lon}
                AND
                LATITUDE BETWEEN ${coordlist[89].lat < coordlist[269].lat ? coordlist[89].lat : coordlist[269].lat} AND ${coordlist[269].lat > coordlist[89].lat ? coordlist[269].lat : coordlist[89].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[90].lon < coordlist[270].lon ? coordlist[90].lon : coordlist[270].lon} AND ${coordlist[270].lon > coordlist[90].lon ? coordlist[270].lon : coordlist[90].lon}
                AND
                LATITUDE BETWEEN ${coordlist[90].lat < coordlist[270].lat ? coordlist[90].lat : coordlist[270].lat} AND ${coordlist[270].lat > coordlist[90].lat ? coordlist[270].lat : coordlist[90].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[91].lon < coordlist[271].lon ? coordlist[91].lon : coordlist[271].lon} AND ${coordlist[271].lon > coordlist[91].lon ? coordlist[271].lon : coordlist[91].lon}
                AND
                LATITUDE BETWEEN ${coordlist[91].lat < coordlist[271].lat ? coordlist[91].lat : coordlist[271].lat} AND ${coordlist[271].lat > coordlist[91].lat ? coordlist[271].lat : coordlist[91].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[92].lon < coordlist[272].lon ? coordlist[92].lon : coordlist[272].lon} AND ${coordlist[272].lon > coordlist[92].lon ? coordlist[272].lon : coordlist[92].lon}
                AND
                LATITUDE BETWEEN ${coordlist[92].lat < coordlist[272].lat ? coordlist[92].lat : coordlist[272].lat} AND ${coordlist[272].lat > coordlist[92].lat ? coordlist[272].lat : coordlist[92].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[93].lon < coordlist[273].lon ? coordlist[93].lon : coordlist[273].lon} AND ${coordlist[273].lon > coordlist[93].lon ? coordlist[273].lon : coordlist[93].lon}
                AND
                LATITUDE BETWEEN ${coordlist[93].lat < coordlist[273].lat ? coordlist[93].lat : coordlist[273].lat} AND ${coordlist[273].lat > coordlist[93].lat ? coordlist[273].lat : coordlist[93].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[94].lon < coordlist[274].lon ? coordlist[94].lon : coordlist[274].lon} AND ${coordlist[274].lon > coordlist[94].lon ? coordlist[274].lon : coordlist[94].lon}
                AND
                LATITUDE BETWEEN ${coordlist[94].lat < coordlist[274].lat ? coordlist[94].lat : coordlist[274].lat} AND ${coordlist[274].lat > coordlist[94].lat ? coordlist[274].lat : coordlist[94].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[95].lon < coordlist[275].lon ? coordlist[95].lon : coordlist[275].lon} AND ${coordlist[275].lon > coordlist[95].lon ? coordlist[275].lon : coordlist[95].lon}
                AND
                LATITUDE BETWEEN ${coordlist[95].lat < coordlist[275].lat ? coordlist[95].lat : coordlist[275].lat} AND ${coordlist[275].lat > coordlist[95].lat ? coordlist[275].lat : coordlist[95].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[96].lon < coordlist[276].lon ? coordlist[96].lon : coordlist[276].lon} AND ${coordlist[276].lon > coordlist[96].lon ? coordlist[276].lon : coordlist[96].lon}
                AND
                LATITUDE BETWEEN ${coordlist[96].lat < coordlist[276].lat ? coordlist[96].lat : coordlist[276].lat} AND ${coordlist[276].lat > coordlist[96].lat ? coordlist[276].lat : coordlist[96].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[97].lon < coordlist[277].lon ? coordlist[97].lon : coordlist[277].lon} AND ${coordlist[277].lon > coordlist[97].lon ? coordlist[277].lon : coordlist[97].lon}
                AND
                LATITUDE BETWEEN ${coordlist[97].lat < coordlist[277].lat ? coordlist[97].lat : coordlist[277].lat} AND ${coordlist[277].lat > coordlist[97].lat ? coordlist[277].lat : coordlist[97].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[98].lon < coordlist[278].lon ? coordlist[98].lon : coordlist[278].lon} AND ${coordlist[278].lon > coordlist[98].lon ? coordlist[278].lon : coordlist[98].lon}
                AND
                LATITUDE BETWEEN ${coordlist[98].lat < coordlist[278].lat ? coordlist[98].lat : coordlist[278].lat} AND ${coordlist[278].lat > coordlist[98].lat ? coordlist[278].lat : coordlist[98].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[99].lon < coordlist[279].lon ? coordlist[99].lon : coordlist[279].lon} AND ${coordlist[279].lon > coordlist[99].lon ? coordlist[279].lon : coordlist[99].lon}
                AND
                LATITUDE BETWEEN ${coordlist[99].lat < coordlist[279].lat ? coordlist[99].lat : coordlist[279].lat} AND ${coordlist[279].lat > coordlist[99].lat ? coordlist[279].lat : coordlist[99].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[100].lon < coordlist[280].lon ? coordlist[100].lon : coordlist[280].lon} AND ${coordlist[280].lon > coordlist[100].lon ? coordlist[280].lon : coordlist[100].lon}
                AND
                LATITUDE BETWEEN ${coordlist[100].lat < coordlist[280].lat ? coordlist[100].lat : coordlist[280].lat} AND ${coordlist[280].lat > coordlist[100].lat ? coordlist[280].lat : coordlist[100].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[101].lon < coordlist[281].lon ? coordlist[101].lon : coordlist[281].lon} AND ${coordlist[281].lon > coordlist[101].lon ? coordlist[281].lon : coordlist[101].lon}
                AND
                LATITUDE BETWEEN ${coordlist[101].lat < coordlist[281].lat ? coordlist[101].lat : coordlist[281].lat} AND ${coordlist[281].lat > coordlist[101].lat ? coordlist[281].lat : coordlist[101].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[102].lon < coordlist[282].lon ? coordlist[102].lon : coordlist[282].lon} AND ${coordlist[282].lon > coordlist[102].lon ? coordlist[282].lon : coordlist[102].lon}
                AND
                LATITUDE BETWEEN ${coordlist[102].lat < coordlist[282].lat ? coordlist[102].lat : coordlist[282].lat} AND ${coordlist[282].lat > coordlist[102].lat ? coordlist[282].lat : coordlist[102].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[103].lon < coordlist[283].lon ? coordlist[103].lon : coordlist[283].lon} AND ${coordlist[283].lon > coordlist[103].lon ? coordlist[283].lon : coordlist[103].lon}
                AND
                LATITUDE BETWEEN ${coordlist[103].lat < coordlist[283].lat ? coordlist[103].lat : coordlist[283].lat} AND ${coordlist[283].lat > coordlist[103].lat ? coordlist[283].lat : coordlist[103].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[104].lon < coordlist[284].lon ? coordlist[104].lon : coordlist[284].lon} AND ${coordlist[284].lon > coordlist[104].lon ? coordlist[284].lon : coordlist[104].lon}
                AND
                LATITUDE BETWEEN ${coordlist[104].lat < coordlist[284].lat ? coordlist[104].lat : coordlist[284].lat} AND ${coordlist[284].lat > coordlist[104].lat ? coordlist[284].lat : coordlist[104].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[105].lon < coordlist[285].lon ? coordlist[105].lon : coordlist[285].lon} AND ${coordlist[285].lon > coordlist[105].lon ? coordlist[285].lon : coordlist[105].lon}
                AND
                LATITUDE BETWEEN ${coordlist[105].lat < coordlist[285].lat ? coordlist[105].lat : coordlist[285].lat} AND ${coordlist[285].lat > coordlist[105].lat ? coordlist[285].lat : coordlist[105].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[106].lon < coordlist[286].lon ? coordlist[106].lon : coordlist[286].lon} AND ${coordlist[286].lon > coordlist[106].lon ? coordlist[286].lon : coordlist[106].lon}
                AND
                LATITUDE BETWEEN ${coordlist[106].lat < coordlist[286].lat ? coordlist[106].lat : coordlist[286].lat} AND ${coordlist[286].lat > coordlist[106].lat ? coordlist[286].lat : coordlist[106].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[107].lon < coordlist[287].lon ? coordlist[107].lon : coordlist[287].lon} AND ${coordlist[287].lon > coordlist[107].lon ? coordlist[287].lon : coordlist[107].lon}
                AND
                LATITUDE BETWEEN ${coordlist[107].lat < coordlist[287].lat ? coordlist[107].lat : coordlist[287].lat} AND ${coordlist[287].lat > coordlist[107].lat ? coordlist[287].lat : coordlist[107].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[108].lon < coordlist[288].lon ? coordlist[108].lon : coordlist[288].lon} AND ${coordlist[288].lon > coordlist[108].lon ? coordlist[288].lon : coordlist[108].lon}
                AND
                LATITUDE BETWEEN ${coordlist[108].lat < coordlist[288].lat ? coordlist[108].lat : coordlist[288].lat} AND ${coordlist[288].lat > coordlist[108].lat ? coordlist[288].lat : coordlist[108].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[109].lon < coordlist[289].lon ? coordlist[109].lon : coordlist[289].lon} AND ${coordlist[289].lon > coordlist[109].lon ? coordlist[289].lon : coordlist[109].lon}
                AND
                LATITUDE BETWEEN ${coordlist[109].lat < coordlist[289].lat ? coordlist[109].lat : coordlist[289].lat} AND ${coordlist[289].lat > coordlist[109].lat ? coordlist[289].lat : coordlist[109].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[110].lon < coordlist[290].lon ? coordlist[110].lon : coordlist[290].lon} AND ${coordlist[290].lon > coordlist[110].lon ? coordlist[290].lon : coordlist[110].lon}
                AND
                LATITUDE BETWEEN ${coordlist[110].lat < coordlist[290].lat ? coordlist[110].lat : coordlist[290].lat} AND ${coordlist[290].lat > coordlist[110].lat ? coordlist[290].lat : coordlist[110].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[111].lon < coordlist[291].lon ? coordlist[111].lon : coordlist[291].lon} AND ${coordlist[291].lon > coordlist[111].lon ? coordlist[291].lon : coordlist[111].lon}
                AND
                LATITUDE BETWEEN ${coordlist[111].lat < coordlist[291].lat ? coordlist[111].lat : coordlist[291].lat} AND ${coordlist[291].lat > coordlist[111].lat ? coordlist[291].lat : coordlist[111].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[112].lon < coordlist[292].lon ? coordlist[112].lon : coordlist[292].lon} AND ${coordlist[292].lon > coordlist[112].lon ? coordlist[292].lon : coordlist[112].lon}
                AND
                LATITUDE BETWEEN ${coordlist[112].lat < coordlist[292].lat ? coordlist[112].lat : coordlist[292].lat} AND ${coordlist[292].lat > coordlist[112].lat ? coordlist[292].lat : coordlist[112].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[113].lon < coordlist[293].lon ? coordlist[113].lon : coordlist[293].lon} AND ${coordlist[293].lon > coordlist[113].lon ? coordlist[293].lon : coordlist[113].lon}
                AND
                LATITUDE BETWEEN ${coordlist[113].lat < coordlist[293].lat ? coordlist[113].lat : coordlist[293].lat} AND ${coordlist[293].lat > coordlist[113].lat ? coordlist[293].lat : coordlist[113].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[114].lon < coordlist[294].lon ? coordlist[114].lon : coordlist[294].lon} AND ${coordlist[294].lon > coordlist[114].lon ? coordlist[294].lon : coordlist[114].lon}
                AND
                LATITUDE BETWEEN ${coordlist[114].lat < coordlist[294].lat ? coordlist[114].lat : coordlist[294].lat} AND ${coordlist[294].lat > coordlist[114].lat ? coordlist[294].lat : coordlist[114].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[115].lon < coordlist[295].lon ? coordlist[115].lon : coordlist[295].lon} AND ${coordlist[295].lon > coordlist[115].lon ? coordlist[295].lon : coordlist[115].lon}
                AND
                LATITUDE BETWEEN ${coordlist[115].lat < coordlist[295].lat ? coordlist[115].lat : coordlist[295].lat} AND ${coordlist[295].lat > coordlist[115].lat ? coordlist[295].lat : coordlist[115].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[116].lon < coordlist[296].lon ? coordlist[116].lon : coordlist[296].lon} AND ${coordlist[296].lon > coordlist[116].lon ? coordlist[296].lon : coordlist[116].lon}
                AND
                LATITUDE BETWEEN ${coordlist[116].lat < coordlist[296].lat ? coordlist[116].lat : coordlist[296].lat} AND ${coordlist[296].lat > coordlist[116].lat ? coordlist[296].lat : coordlist[116].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[117].lon < coordlist[297].lon ? coordlist[117].lon : coordlist[297].lon} AND ${coordlist[297].lon > coordlist[117].lon ? coordlist[297].lon : coordlist[117].lon}
                AND
                LATITUDE BETWEEN ${coordlist[117].lat < coordlist[297].lat ? coordlist[117].lat : coordlist[297].lat} AND ${coordlist[297].lat > coordlist[117].lat ? coordlist[297].lat : coordlist[117].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[118].lon < coordlist[298].lon ? coordlist[118].lon : coordlist[298].lon} AND ${coordlist[298].lon > coordlist[118].lon ? coordlist[298].lon : coordlist[118].lon}
                AND
                LATITUDE BETWEEN ${coordlist[118].lat < coordlist[298].lat ? coordlist[118].lat : coordlist[298].lat} AND ${coordlist[298].lat > coordlist[118].lat ? coordlist[298].lat : coordlist[118].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[119].lon < coordlist[299].lon ? coordlist[119].lon : coordlist[299].lon} AND ${coordlist[299].lon > coordlist[119].lon ? coordlist[299].lon : coordlist[119].lon}
                AND
                LATITUDE BETWEEN ${coordlist[119].lat < coordlist[299].lat ? coordlist[119].lat : coordlist[299].lat} AND ${coordlist[299].lat > coordlist[119].lat ? coordlist[299].lat : coordlist[119].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[120].lon < coordlist[300].lon ? coordlist[120].lon : coordlist[300].lon} AND ${coordlist[300].lon > coordlist[120].lon ? coordlist[300].lon : coordlist[120].lon}
                AND
                LATITUDE BETWEEN ${coordlist[120].lat < coordlist[300].lat ? coordlist[120].lat : coordlist[300].lat} AND ${coordlist[300].lat > coordlist[120].lat ? coordlist[300].lat : coordlist[120].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[121].lon < coordlist[301].lon ? coordlist[121].lon : coordlist[301].lon} AND ${coordlist[301].lon > coordlist[121].lon ? coordlist[301].lon : coordlist[121].lon}
                AND
                LATITUDE BETWEEN ${coordlist[121].lat < coordlist[301].lat ? coordlist[121].lat : coordlist[301].lat} AND ${coordlist[301].lat > coordlist[121].lat ? coordlist[301].lat : coordlist[121].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[122].lon < coordlist[302].lon ? coordlist[122].lon : coordlist[302].lon} AND ${coordlist[302].lon > coordlist[122].lon ? coordlist[302].lon : coordlist[122].lon}
                AND
                LATITUDE BETWEEN ${coordlist[122].lat < coordlist[302].lat ? coordlist[122].lat : coordlist[302].lat} AND ${coordlist[302].lat > coordlist[122].lat ? coordlist[302].lat : coordlist[122].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[123].lon < coordlist[303].lon ? coordlist[123].lon : coordlist[303].lon} AND ${coordlist[303].lon > coordlist[123].lon ? coordlist[303].lon : coordlist[123].lon}
                AND
                LATITUDE BETWEEN ${coordlist[123].lat < coordlist[303].lat ? coordlist[123].lat : coordlist[303].lat} AND ${coordlist[303].lat > coordlist[123].lat ? coordlist[303].lat : coordlist[123].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[124].lon < coordlist[304].lon ? coordlist[124].lon : coordlist[304].lon} AND ${coordlist[304].lon > coordlist[124].lon ? coordlist[304].lon : coordlist[124].lon}
                AND
                LATITUDE BETWEEN ${coordlist[124].lat < coordlist[304].lat ? coordlist[124].lat : coordlist[304].lat} AND ${coordlist[304].lat > coordlist[124].lat ? coordlist[304].lat : coordlist[124].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[125].lon < coordlist[305].lon ? coordlist[125].lon : coordlist[305].lon} AND ${coordlist[305].lon > coordlist[125].lon ? coordlist[305].lon : coordlist[125].lon}
                AND
                LATITUDE BETWEEN ${coordlist[125].lat < coordlist[305].lat ? coordlist[125].lat : coordlist[305].lat} AND ${coordlist[305].lat > coordlist[125].lat ? coordlist[305].lat : coordlist[125].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[126].lon < coordlist[306].lon ? coordlist[126].lon : coordlist[306].lon} AND ${coordlist[306].lon > coordlist[126].lon ? coordlist[306].lon : coordlist[126].lon}
                AND
                LATITUDE BETWEEN ${coordlist[126].lat < coordlist[306].lat ? coordlist[126].lat : coordlist[306].lat} AND ${coordlist[306].lat > coordlist[126].lat ? coordlist[306].lat : coordlist[126].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[127].lon < coordlist[307].lon ? coordlist[127].lon : coordlist[307].lon} AND ${coordlist[307].lon > coordlist[127].lon ? coordlist[307].lon : coordlist[127].lon}
                AND
                LATITUDE BETWEEN ${coordlist[127].lat < coordlist[307].lat ? coordlist[127].lat : coordlist[307].lat} AND ${coordlist[307].lat > coordlist[127].lat ? coordlist[307].lat : coordlist[127].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[128].lon < coordlist[308].lon ? coordlist[128].lon : coordlist[308].lon} AND ${coordlist[308].lon > coordlist[128].lon ? coordlist[308].lon : coordlist[128].lon}
                AND
                LATITUDE BETWEEN ${coordlist[128].lat < coordlist[308].lat ? coordlist[128].lat : coordlist[308].lat} AND ${coordlist[308].lat > coordlist[128].lat ? coordlist[308].lat : coordlist[128].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[129].lon < coordlist[309].lon ? coordlist[129].lon : coordlist[309].lon} AND ${coordlist[309].lon > coordlist[129].lon ? coordlist[309].lon : coordlist[129].lon}
                AND
                LATITUDE BETWEEN ${coordlist[129].lat < coordlist[309].lat ? coordlist[129].lat : coordlist[309].lat} AND ${coordlist[309].lat > coordlist[129].lat ? coordlist[309].lat : coordlist[129].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[130].lon < coordlist[310].lon ? coordlist[130].lon : coordlist[310].lon} AND ${coordlist[310].lon > coordlist[130].lon ? coordlist[310].lon : coordlist[130].lon}
                AND
                LATITUDE BETWEEN ${coordlist[130].lat < coordlist[310].lat ? coordlist[130].lat : coordlist[310].lat} AND ${coordlist[310].lat > coordlist[130].lat ? coordlist[310].lat : coordlist[130].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[131].lon < coordlist[311].lon ? coordlist[131].lon : coordlist[311].lon} AND ${coordlist[311].lon > coordlist[131].lon ? coordlist[311].lon : coordlist[131].lon}
                AND
                LATITUDE BETWEEN ${coordlist[131].lat < coordlist[311].lat ? coordlist[131].lat : coordlist[311].lat} AND ${coordlist[311].lat > coordlist[131].lat ? coordlist[311].lat : coordlist[131].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[132].lon < coordlist[312].lon ? coordlist[132].lon : coordlist[312].lon} AND ${coordlist[312].lon > coordlist[132].lon ? coordlist[312].lon : coordlist[132].lon}
                AND
                LATITUDE BETWEEN ${coordlist[132].lat < coordlist[312].lat ? coordlist[132].lat : coordlist[312].lat} AND ${coordlist[312].lat > coordlist[132].lat ? coordlist[312].lat : coordlist[132].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[133].lon < coordlist[313].lon ? coordlist[133].lon : coordlist[313].lon} AND ${coordlist[313].lon > coordlist[133].lon ? coordlist[313].lon : coordlist[133].lon}
                AND
                LATITUDE BETWEEN ${coordlist[133].lat < coordlist[313].lat ? coordlist[133].lat : coordlist[313].lat} AND ${coordlist[313].lat > coordlist[133].lat ? coordlist[313].lat : coordlist[133].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[134].lon < coordlist[314].lon ? coordlist[134].lon : coordlist[314].lon} AND ${coordlist[314].lon > coordlist[134].lon ? coordlist[314].lon : coordlist[134].lon}
                AND
                LATITUDE BETWEEN ${coordlist[134].lat < coordlist[314].lat ? coordlist[134].lat : coordlist[314].lat} AND ${coordlist[314].lat > coordlist[134].lat ? coordlist[314].lat : coordlist[134].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[135].lon < coordlist[315].lon ? coordlist[135].lon : coordlist[315].lon} AND ${coordlist[315].lon > coordlist[135].lon ? coordlist[315].lon : coordlist[135].lon}
                AND
                LATITUDE BETWEEN ${coordlist[135].lat < coordlist[315].lat ? coordlist[135].lat : coordlist[315].lat} AND ${coordlist[315].lat > coordlist[135].lat ? coordlist[315].lat : coordlist[135].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[136].lon < coordlist[316].lon ? coordlist[136].lon : coordlist[316].lon} AND ${coordlist[316].lon > coordlist[136].lon ? coordlist[316].lon : coordlist[136].lon}
                AND
                LATITUDE BETWEEN ${coordlist[136].lat < coordlist[316].lat ? coordlist[136].lat : coordlist[316].lat} AND ${coordlist[316].lat > coordlist[136].lat ? coordlist[316].lat : coordlist[136].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[137].lon < coordlist[317].lon ? coordlist[137].lon : coordlist[317].lon} AND ${coordlist[317].lon > coordlist[137].lon ? coordlist[317].lon : coordlist[137].lon}
                AND
                LATITUDE BETWEEN ${coordlist[137].lat < coordlist[317].lat ? coordlist[137].lat : coordlist[317].lat} AND ${coordlist[317].lat > coordlist[137].lat ? coordlist[317].lat : coordlist[137].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[138].lon < coordlist[318].lon ? coordlist[138].lon : coordlist[318].lon} AND ${coordlist[318].lon > coordlist[138].lon ? coordlist[318].lon : coordlist[138].lon}
                AND
                LATITUDE BETWEEN ${coordlist[138].lat < coordlist[318].lat ? coordlist[138].lat : coordlist[318].lat} AND ${coordlist[318].lat > coordlist[138].lat ? coordlist[318].lat : coordlist[138].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[139].lon < coordlist[319].lon ? coordlist[139].lon : coordlist[319].lon} AND ${coordlist[319].lon > coordlist[139].lon ? coordlist[319].lon : coordlist[139].lon}
                AND
                LATITUDE BETWEEN ${coordlist[139].lat < coordlist[319].lat ? coordlist[139].lat : coordlist[319].lat} AND ${coordlist[319].lat > coordlist[139].lat ? coordlist[319].lat : coordlist[139].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[140].lon < coordlist[320].lon ? coordlist[140].lon : coordlist[320].lon} AND ${coordlist[320].lon > coordlist[140].lon ? coordlist[320].lon : coordlist[140].lon}
                AND
                LATITUDE BETWEEN ${coordlist[140].lat < coordlist[320].lat ? coordlist[140].lat : coordlist[320].lat} AND ${coordlist[320].lat > coordlist[140].lat ? coordlist[320].lat : coordlist[140].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[141].lon < coordlist[321].lon ? coordlist[141].lon : coordlist[321].lon} AND ${coordlist[321].lon > coordlist[141].lon ? coordlist[321].lon : coordlist[141].lon}
                AND
                LATITUDE BETWEEN ${coordlist[141].lat < coordlist[321].lat ? coordlist[141].lat : coordlist[321].lat} AND ${coordlist[321].lat > coordlist[141].lat ? coordlist[321].lat : coordlist[141].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[142].lon < coordlist[322].lon ? coordlist[142].lon : coordlist[322].lon} AND ${coordlist[322].lon > coordlist[142].lon ? coordlist[322].lon : coordlist[142].lon}
                AND
                LATITUDE BETWEEN ${coordlist[142].lat < coordlist[322].lat ? coordlist[142].lat : coordlist[322].lat} AND ${coordlist[322].lat > coordlist[142].lat ? coordlist[322].lat : coordlist[142].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[143].lon < coordlist[323].lon ? coordlist[143].lon : coordlist[323].lon} AND ${coordlist[323].lon > coordlist[143].lon ? coordlist[323].lon : coordlist[143].lon}
                AND
                LATITUDE BETWEEN ${coordlist[143].lat < coordlist[323].lat ? coordlist[143].lat : coordlist[323].lat} AND ${coordlist[323].lat > coordlist[143].lat ? coordlist[323].lat : coordlist[143].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[144].lon < coordlist[324].lon ? coordlist[144].lon : coordlist[324].lon} AND ${coordlist[324].lon > coordlist[144].lon ? coordlist[324].lon : coordlist[144].lon}
                AND
                LATITUDE BETWEEN ${coordlist[144].lat < coordlist[324].lat ? coordlist[144].lat : coordlist[324].lat} AND ${coordlist[324].lat > coordlist[144].lat ? coordlist[324].lat : coordlist[144].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[145].lon < coordlist[325].lon ? coordlist[145].lon : coordlist[325].lon} AND ${coordlist[325].lon > coordlist[145].lon ? coordlist[325].lon : coordlist[145].lon}
                AND
                LATITUDE BETWEEN ${coordlist[145].lat < coordlist[325].lat ? coordlist[145].lat : coordlist[325].lat} AND ${coordlist[325].lat > coordlist[145].lat ? coordlist[325].lat : coordlist[145].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[146].lon < coordlist[326].lon ? coordlist[146].lon : coordlist[326].lon} AND ${coordlist[326].lon > coordlist[146].lon ? coordlist[326].lon : coordlist[146].lon}
                AND
                LATITUDE BETWEEN ${coordlist[146].lat < coordlist[326].lat ? coordlist[146].lat : coordlist[326].lat} AND ${coordlist[326].lat > coordlist[146].lat ? coordlist[326].lat : coordlist[146].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[147].lon < coordlist[327].lon ? coordlist[147].lon : coordlist[327].lon} AND ${coordlist[327].lon > coordlist[147].lon ? coordlist[327].lon : coordlist[147].lon}
                AND
                LATITUDE BETWEEN ${coordlist[147].lat < coordlist[327].lat ? coordlist[147].lat : coordlist[327].lat} AND ${coordlist[327].lat > coordlist[147].lat ? coordlist[327].lat : coordlist[147].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[148].lon < coordlist[328].lon ? coordlist[148].lon : coordlist[328].lon} AND ${coordlist[328].lon > coordlist[148].lon ? coordlist[328].lon : coordlist[148].lon}
                AND
                LATITUDE BETWEEN ${coordlist[148].lat < coordlist[328].lat ? coordlist[148].lat : coordlist[328].lat} AND ${coordlist[328].lat > coordlist[148].lat ? coordlist[328].lat : coordlist[148].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[149].lon < coordlist[329].lon ? coordlist[149].lon : coordlist[329].lon} AND ${coordlist[329].lon > coordlist[149].lon ? coordlist[329].lon : coordlist[149].lon}
                AND
                LATITUDE BETWEEN ${coordlist[149].lat < coordlist[329].lat ? coordlist[149].lat : coordlist[329].lat} AND ${coordlist[329].lat > coordlist[149].lat ? coordlist[329].lat : coordlist[149].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[150].lon < coordlist[330].lon ? coordlist[150].lon : coordlist[330].lon} AND ${coordlist[330].lon > coordlist[150].lon ? coordlist[330].lon : coordlist[150].lon}
                AND
                LATITUDE BETWEEN ${coordlist[150].lat < coordlist[330].lat ? coordlist[150].lat : coordlist[330].lat} AND ${coordlist[330].lat > coordlist[150].lat ? coordlist[330].lat : coordlist[150].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[151].lon < coordlist[331].lon ? coordlist[151].lon : coordlist[331].lon} AND ${coordlist[331].lon > coordlist[151].lon ? coordlist[331].lon : coordlist[151].lon}
                AND
                LATITUDE BETWEEN ${coordlist[151].lat < coordlist[331].lat ? coordlist[151].lat : coordlist[331].lat} AND ${coordlist[331].lat > coordlist[151].lat ? coordlist[331].lat : coordlist[151].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[152].lon < coordlist[332].lon ? coordlist[152].lon : coordlist[332].lon} AND ${coordlist[332].lon > coordlist[152].lon ? coordlist[332].lon : coordlist[152].lon}
                AND
                LATITUDE BETWEEN ${coordlist[152].lat < coordlist[332].lat ? coordlist[152].lat : coordlist[332].lat} AND ${coordlist[332].lat > coordlist[152].lat ? coordlist[332].lat : coordlist[152].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[153].lon < coordlist[333].lon ? coordlist[153].lon : coordlist[333].lon} AND ${coordlist[333].lon > coordlist[153].lon ? coordlist[333].lon : coordlist[153].lon}
                AND
                LATITUDE BETWEEN ${coordlist[153].lat < coordlist[333].lat ? coordlist[153].lat : coordlist[333].lat} AND ${coordlist[333].lat > coordlist[153].lat ? coordlist[333].lat : coordlist[153].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[154].lon < coordlist[334].lon ? coordlist[154].lon : coordlist[334].lon} AND ${coordlist[334].lon > coordlist[154].lon ? coordlist[334].lon : coordlist[154].lon}
                AND
                LATITUDE BETWEEN ${coordlist[154].lat < coordlist[334].lat ? coordlist[154].lat : coordlist[334].lat} AND ${coordlist[334].lat > coordlist[154].lat ? coordlist[334].lat : coordlist[154].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[155].lon < coordlist[335].lon ? coordlist[155].lon : coordlist[335].lon} AND ${coordlist[335].lon > coordlist[155].lon ? coordlist[335].lon : coordlist[155].lon}
                AND
                LATITUDE BETWEEN ${coordlist[155].lat < coordlist[335].lat ? coordlist[155].lat : coordlist[335].lat} AND ${coordlist[335].lat > coordlist[155].lat ? coordlist[335].lat : coordlist[155].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[156].lon < coordlist[336].lon ? coordlist[156].lon : coordlist[336].lon} AND ${coordlist[336].lon > coordlist[156].lon ? coordlist[336].lon : coordlist[156].lon}
                AND
                LATITUDE BETWEEN ${coordlist[156].lat < coordlist[336].lat ? coordlist[156].lat : coordlist[336].lat} AND ${coordlist[336].lat > coordlist[156].lat ? coordlist[336].lat : coordlist[156].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[157].lon < coordlist[337].lon ? coordlist[157].lon : coordlist[337].lon} AND ${coordlist[337].lon > coordlist[157].lon ? coordlist[337].lon : coordlist[157].lon}
                AND
                LATITUDE BETWEEN ${coordlist[157].lat < coordlist[337].lat ? coordlist[157].lat : coordlist[337].lat} AND ${coordlist[337].lat > coordlist[157].lat ? coordlist[337].lat : coordlist[157].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[158].lon < coordlist[338].lon ? coordlist[158].lon : coordlist[338].lon} AND ${coordlist[338].lon > coordlist[158].lon ? coordlist[338].lon : coordlist[158].lon}
                AND
                LATITUDE BETWEEN ${coordlist[158].lat < coordlist[338].lat ? coordlist[158].lat : coordlist[338].lat} AND ${coordlist[338].lat > coordlist[158].lat ? coordlist[338].lat : coordlist[158].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[159].lon < coordlist[339].lon ? coordlist[159].lon : coordlist[339].lon} AND ${coordlist[339].lon > coordlist[159].lon ? coordlist[339].lon : coordlist[159].lon}
                AND
                LATITUDE BETWEEN ${coordlist[159].lat < coordlist[339].lat ? coordlist[159].lat : coordlist[339].lat} AND ${coordlist[339].lat > coordlist[159].lat ? coordlist[339].lat : coordlist[159].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[160].lon < coordlist[340].lon ? coordlist[160].lon : coordlist[340].lon} AND ${coordlist[340].lon > coordlist[160].lon ? coordlist[340].lon : coordlist[160].lon}
                AND
                LATITUDE BETWEEN ${coordlist[160].lat < coordlist[340].lat ? coordlist[160].lat : coordlist[340].lat} AND ${coordlist[340].lat > coordlist[160].lat ? coordlist[340].lat : coordlist[160].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[161].lon < coordlist[341].lon ? coordlist[161].lon : coordlist[341].lon} AND ${coordlist[341].lon > coordlist[161].lon ? coordlist[341].lon : coordlist[161].lon}
                AND
                LATITUDE BETWEEN ${coordlist[161].lat < coordlist[341].lat ? coordlist[161].lat : coordlist[341].lat} AND ${coordlist[341].lat > coordlist[161].lat ? coordlist[341].lat : coordlist[161].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[162].lon < coordlist[342].lon ? coordlist[162].lon : coordlist[342].lon} AND ${coordlist[342].lon > coordlist[162].lon ? coordlist[342].lon : coordlist[162].lon}
                AND
                LATITUDE BETWEEN ${coordlist[162].lat < coordlist[342].lat ? coordlist[162].lat : coordlist[342].lat} AND ${coordlist[342].lat > coordlist[162].lat ? coordlist[342].lat : coordlist[162].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[163].lon < coordlist[343].lon ? coordlist[163].lon : coordlist[343].lon} AND ${coordlist[343].lon > coordlist[163].lon ? coordlist[343].lon : coordlist[163].lon}
                AND
                LATITUDE BETWEEN ${coordlist[163].lat < coordlist[343].lat ? coordlist[163].lat : coordlist[343].lat} AND ${coordlist[343].lat > coordlist[163].lat ? coordlist[343].lat : coordlist[163].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[164].lon < coordlist[344].lon ? coordlist[164].lon : coordlist[344].lon} AND ${coordlist[344].lon > coordlist[164].lon ? coordlist[344].lon : coordlist[164].lon}
                AND
                LATITUDE BETWEEN ${coordlist[164].lat < coordlist[344].lat ? coordlist[164].lat : coordlist[344].lat} AND ${coordlist[344].lat > coordlist[164].lat ? coordlist[344].lat : coordlist[164].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[165].lon < coordlist[345].lon ? coordlist[165].lon : coordlist[345].lon} AND ${coordlist[345].lon > coordlist[165].lon ? coordlist[345].lon : coordlist[165].lon}
                AND
                LATITUDE BETWEEN ${coordlist[165].lat < coordlist[345].lat ? coordlist[165].lat : coordlist[345].lat} AND ${coordlist[345].lat > coordlist[165].lat ? coordlist[345].lat : coordlist[165].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[166].lon < coordlist[346].lon ? coordlist[166].lon : coordlist[346].lon} AND ${coordlist[346].lon > coordlist[166].lon ? coordlist[346].lon : coordlist[166].lon}
                AND
                LATITUDE BETWEEN ${coordlist[166].lat < coordlist[346].lat ? coordlist[166].lat : coordlist[346].lat} AND ${coordlist[346].lat > coordlist[166].lat ? coordlist[346].lat : coordlist[166].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[167].lon < coordlist[347].lon ? coordlist[167].lon : coordlist[347].lon} AND ${coordlist[347].lon > coordlist[167].lon ? coordlist[347].lon : coordlist[167].lon}
                AND
                LATITUDE BETWEEN ${coordlist[167].lat < coordlist[347].lat ? coordlist[167].lat : coordlist[347].lat} AND ${coordlist[347].lat > coordlist[167].lat ? coordlist[347].lat : coordlist[167].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[168].lon < coordlist[348].lon ? coordlist[168].lon : coordlist[348].lon} AND ${coordlist[348].lon > coordlist[168].lon ? coordlist[348].lon : coordlist[168].lon}
                AND
                LATITUDE BETWEEN ${coordlist[168].lat < coordlist[348].lat ? coordlist[168].lat : coordlist[348].lat} AND ${coordlist[348].lat > coordlist[168].lat ? coordlist[348].lat : coordlist[168].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[169].lon < coordlist[349].lon ? coordlist[169].lon : coordlist[349].lon} AND ${coordlist[349].lon > coordlist[169].lon ? coordlist[349].lon : coordlist[169].lon}
                AND
                LATITUDE BETWEEN ${coordlist[169].lat < coordlist[349].lat ? coordlist[169].lat : coordlist[349].lat} AND ${coordlist[349].lat > coordlist[169].lat ? coordlist[349].lat : coordlist[169].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[170].lon < coordlist[350].lon ? coordlist[170].lon : coordlist[350].lon} AND ${coordlist[350].lon > coordlist[170].lon ? coordlist[350].lon : coordlist[170].lon}
                AND
                LATITUDE BETWEEN ${coordlist[170].lat < coordlist[350].lat ? coordlist[170].lat : coordlist[350].lat} AND ${coordlist[350].lat > coordlist[170].lat ? coordlist[350].lat : coordlist[170].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[171].lon < coordlist[351].lon ? coordlist[171].lon : coordlist[351].lon} AND ${coordlist[351].lon > coordlist[171].lon ? coordlist[351].lon : coordlist[171].lon}
                AND
                LATITUDE BETWEEN ${coordlist[171].lat < coordlist[351].lat ? coordlist[171].lat : coordlist[351].lat} AND ${coordlist[351].lat > coordlist[171].lat ? coordlist[351].lat : coordlist[171].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[172].lon < coordlist[352].lon ? coordlist[172].lon : coordlist[352].lon} AND ${coordlist[352].lon > coordlist[172].lon ? coordlist[352].lon : coordlist[172].lon}
                AND
                LATITUDE BETWEEN ${coordlist[172].lat < coordlist[352].lat ? coordlist[172].lat : coordlist[352].lat} AND ${coordlist[352].lat > coordlist[172].lat ? coordlist[352].lat : coordlist[172].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[173].lon < coordlist[353].lon ? coordlist[173].lon : coordlist[353].lon} AND ${coordlist[353].lon > coordlist[173].lon ? coordlist[353].lon : coordlist[173].lon}
                AND
                LATITUDE BETWEEN ${coordlist[173].lat < coordlist[353].lat ? coordlist[173].lat : coordlist[353].lat} AND ${coordlist[353].lat > coordlist[173].lat ? coordlist[353].lat : coordlist[173].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[174].lon < coordlist[354].lon ? coordlist[174].lon : coordlist[354].lon} AND ${coordlist[354].lon > coordlist[174].lon ? coordlist[354].lon : coordlist[174].lon}
                AND
                LATITUDE BETWEEN ${coordlist[174].lat < coordlist[354].lat ? coordlist[174].lat : coordlist[354].lat} AND ${coordlist[354].lat > coordlist[174].lat ? coordlist[354].lat : coordlist[174].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[175].lon < coordlist[355].lon ? coordlist[175].lon : coordlist[355].lon} AND ${coordlist[355].lon > coordlist[175].lon ? coordlist[355].lon : coordlist[175].lon}
                AND
                LATITUDE BETWEEN ${coordlist[175].lat < coordlist[355].lat ? coordlist[175].lat : coordlist[355].lat} AND ${coordlist[355].lat > coordlist[175].lat ? coordlist[355].lat : coordlist[175].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[176].lon < coordlist[356].lon ? coordlist[176].lon : coordlist[356].lon} AND ${coordlist[356].lon > coordlist[176].lon ? coordlist[356].lon : coordlist[176].lon}
                AND
                LATITUDE BETWEEN ${coordlist[176].lat < coordlist[356].lat ? coordlist[176].lat : coordlist[356].lat} AND ${coordlist[356].lat > coordlist[176].lat ? coordlist[356].lat : coordlist[176].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[177].lon < coordlist[357].lon ? coordlist[177].lon : coordlist[357].lon} AND ${coordlist[357].lon > coordlist[177].lon ? coordlist[357].lon : coordlist[177].lon}
                AND
                LATITUDE BETWEEN ${coordlist[177].lat < coordlist[357].lat ? coordlist[177].lat : coordlist[357].lat} AND ${coordlist[357].lat > coordlist[177].lat ? coordlist[357].lat : coordlist[177].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[178].lon < coordlist[358].lon ? coordlist[178].lon : coordlist[358].lon} AND ${coordlist[358].lon > coordlist[178].lon ? coordlist[358].lon : coordlist[178].lon}
                AND
                LATITUDE BETWEEN ${coordlist[178].lat < coordlist[358].lat ? coordlist[178].lat : coordlist[358].lat} AND ${coordlist[358].lat > coordlist[178].lat ? coordlist[358].lat : coordlist[178].lat})
                OR
                (LONGITUDE BETWEEN ${coordlist[179].lon < coordlist[359].lon ? coordlist[179].lon : coordlist[359].lon} AND ${coordlist[359].lon > coordlist[179].lon ? coordlist[359].lon : coordlist[179].lon}
                AND
                LATITUDE BETWEEN ${coordlist[179].lat < coordlist[359].lat ? coordlist[179].lat : coordlist[359].lat} AND ${coordlist[359].lat > coordlist[179].lat ? coordlist[359].lat : coordlist[179].lat}))
    `
}

module.exports = { storeQuery }